/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/nats-io/nats"
)

var nc *nats.Conn
var natsErr error

func processEvent(data []byte) (*Event, error) {
	var ev Event
	err := json.Unmarshal(data, &ev)
	return &ev, err
}

func eventHandler(m *nats.Msg) {
	f, err := processEvent(m.Data)
	if err != nil {
		nc.Publish("firewall.create.aws.error", m.Data)
		return
	}

	if f.Valid() == false {
		f.Error(errors.New("Security Group is invalid"))
		return
	}

	err = createFirewall(f)
	if err != nil {
		f.Error(err)
		return
	}

	f.Complete()
}

func buildPermissions(rules []rule) []*ec2.IpPermission {
	var perms []*ec2.IpPermission
	for _, rule := range rules {
		p := ec2.IpPermission{
			FromPort:   aws.Int64(rule.FromPort),
			ToPort:     aws.Int64(rule.ToPort),
			IpProtocol: aws.String(rule.Protocol),
		}
		ip := ec2.IpRange{CidrIp: aws.String(rule.IP)}
		p.IpRanges = append(p.IpRanges, &ip)
		perms = append(perms, &p)
	}
	return perms
}

func createFirewall(ev *Event) error {
	creds := credentials.NewStaticCredentials(ev.DatacenterAccessKey, ev.DatacenterAccessToken, "")
	svc := ec2.New(session.New(), &aws.Config{
		Region:      aws.String(ev.DatacenterRegion),
		Credentials: creds,
	})

	// Create SecurityGroup
	req := ec2.CreateSecurityGroupInput{
		VpcId:       aws.String(ev.DatacenterVPCID),
		GroupName:   aws.String(ev.SecurityGroupName),
		Description: aws.String("Rules for: " + ev.SecurityGroupName),
	}

	resp, err := svc.CreateSecurityGroup(&req)
	if err != nil {
		return err
	}

	ev.SecurityGroupAWSID = *resp.GroupId

	// Authorize Ingress
	if len(ev.SecurityGroupRules.Ingress) > 0 {
		iReq := ec2.AuthorizeSecurityGroupIngressInput{
			GroupId:       aws.String(ev.SecurityGroupAWSID),
			IpPermissions: buildPermissions(ev.SecurityGroupRules.Ingress),
		}

		_, err = svc.AuthorizeSecurityGroupIngress(&iReq)
		if err != nil {
			return err
		}
	}

	// Authorize Egress
	if len(ev.SecurityGroupRules.Egress) > 0 {
		eReq := ec2.AuthorizeSecurityGroupEgressInput{
			GroupId:       aws.String(ev.SecurityGroupAWSID),
			IpPermissions: buildPermissions(ev.SecurityGroupRules.Egress),
		}

		_, err = svc.AuthorizeSecurityGroupEgress(&eReq)
		if err != nil {
			return err
		}
	}

	return nil
}

func main() {
	natsURI := os.Getenv("NATS_URI")
	if natsURI == "" {
		natsURI = nats.DefaultURL
	}

	nc, natsErr = nats.Connect(natsURI)
	if natsErr != nil {
		log.Fatal(natsErr)
	}

	fmt.Println("listening for firewall.create.aws")
	nc.Subscribe("firewall.create.aws", eventHandler)

	runtime.Goexit()
}
