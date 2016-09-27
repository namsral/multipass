// Copyright 2016 Lars Wiegman. All rights reserved. Use of this source code is
// governed by a BSD-style license that can be found in the LICENSE file.

package email_test

import (
	"fmt"

	"github.com/namsral/multipass/services/email"
)

func ExampleSplitLocalDomain() {
	local, domain, err := email.SplitLocalDomain("bob@example.com")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(local, domain)
	// Output: bob example.com
}
