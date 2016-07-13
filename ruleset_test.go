/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestRuleset(t *testing.T) {
	ev := testEvent
	buildTestRules(&ev)

	Convey("Given an ruleset", t, func() {
		Convey("When mapping to IpPermissions", func() {
			ruleset := buildPermissions(ev.SecurityGroupRules.Ingress)
			Convey("It should produce the correct output", func() {
				So(len(ruleset), ShouldEqual, 1)
				So(*ruleset[0].IpRanges[0].CidrIp, ShouldEqual, "10.0.10.100/32")
				So(*ruleset[0].FromPort, ShouldEqual, 80)
				So(*ruleset[0].ToPort, ShouldEqual, 8080)
				So(*ruleset[0].IpProtocol, ShouldEqual, "tcp")
			})
		})
	})
}
