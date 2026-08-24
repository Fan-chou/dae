/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/stretchr/testify/require"
)

func TestNewDialerSelectionPolicyFromGroupParamRejectsInvalidPolicyType(t *testing.T) {
	_, err := NewDialerSelectionPolicyFromGroupParam(&config.Group{
		Policy: 123,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported function-list-or-string value type")
}

func TestNewDialerSelectionPolicyFromGroupParamParsesFirstAlive(t *testing.T) {
	policy, err := NewDialerSelectionPolicyFromGroupParam(&config.Group{
		Policy: "first_alive",
	})
	require.NoError(t, err)
	require.Equal(t, consts.DialerSelectionPolicy_FirstAlive, policy.Policy)
	require.Zero(t, policy.FixedIndex)
}

func TestNewDialerSelectionPolicyFromGroupParamParsesFallbackAndUrlTest(t *testing.T) {
	fallback, err := NewDialerSelectionPolicyFromGroupParam(&config.Group{Policy: "fallback"})
	require.NoError(t, err)
	require.Equal(t, consts.DialerSelectionPolicy_Fallback, fallback.Policy)

	urlTest, err := NewDialerSelectionPolicyFromGroupParam(&config.Group{Policy: "url_test"})
	require.NoError(t, err)
	require.Equal(t, consts.DialerSelectionPolicy_UrlTest, urlTest.Policy)
}
