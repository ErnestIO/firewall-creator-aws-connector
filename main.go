/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	ecc "github.com/ernestio/ernest-config-client"
	"github.com/nats-io/nats"
)

var nc *nats.Conn
var natsErr error

func eventHandler(m *nats.Msg) {
	var f Event

	err := f.Process(m.Data)
	if err != nil {
		return
	}

	if err = f.Validate(); err != nil {
		f.Error(err)
		return
	}

	err = createFirewall(&f)
	if err != nil {
		f.Error(err)
		return
	}

	f.Complete()
}

func removeDefaultRule(svc *ec2.EC2, sgID *string) error {
	perms := []*ec2.IpPermission{
		&ec2.IpPermission{
			FromPort:   aws.Int64(0),
			ToPort:     aws.Int64(65535),
			IpProtocol: aws.String("-1"),
			IpRanges: []*ec2.IpRange{
				&ec2.IpRange{CidrIp: aws.String("0.0.0.0/0")},
			},
		},
	}

	eReq := ec2.RevokeSecurityGroupEgressInput{
		GroupId:       sgID,
		IpPermissions: perms,
	}
	_, err := svc.RevokeSecurityGroupEgress(&eReq)
	return err
}

func createFirewall(ev *Event) error {
	creds := credentials.NewStaticCredentials(ev.DatacenterAccessKey, ev.DatacenterAccessToken, "")
	svc := ec2.New(session.New(), &aws.Config{
		Region:      aws.String(ev.DatacenterRegion),
		Credentials: creds,
	})

	// Create SecurityGroup
	req := ec2.CreateSecurityGroupInput{
		VpcId:       aws.String(ev.VPCID),
		GroupName:   aws.String(ev.SecurityGroupName),
		Description: aws.String("Rules for: " + ev.SecurityGroupName),
	}

	resp, err := svc.CreateSecurityGroup(&req)
	if err != nil {
		return err
	}

	ev.SecurityGroupAWSID = *resp.GroupId

	// Remove default rule
	err = removeDefaultRule(svc, resp.GroupId)
	if err != nil {
		return err
	}

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
	nc = ecc.NewConfig(os.Getenv("NATS_URI")).Nats()

	fmt.Println("listening for firewall.create.aws")
	nc.Subscribe("firewall.create.aws", eventHandler)

	runtime.Goexit()
}
