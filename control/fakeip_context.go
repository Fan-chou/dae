/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
)

type fakeIPStoreContextKey struct{}

func WithFakeIPStore(ctx context.Context, store *FakeIPStore) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, fakeIPStoreContextKey{}, store)
}

func fakeIPStoreFromContext(ctx context.Context) *FakeIPStore {
	if ctx == nil {
		return nil
	}
	store, _ := ctx.Value(fakeIPStoreContextKey{}).(*FakeIPStore)
	return store
}
