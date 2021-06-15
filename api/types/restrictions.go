/*
Copyright 2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package types

import (
	"time"

	"github.com/gravitational/trace"
)

// NewNetworkRestrictions creates a new NetworkRestrictions with the given name.
func NewNetworkRestrictions(name, id string, addedAt time.Time) *NetworkRestrictions{
	return &NetworkRestrictions{
		Kind: KindNetworkRestrictions,
		Version: V1,
		Metadata: Metadata{
			Name: name,
		},
	}
}

// CheckAndSetDefaults validates NetworkRestrictions fields and populates empty fields
// with default values.
func (r *NetworkRestrictions) CheckAndSetDefaults() error {
	if err := r.Metadata.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	if r.Kind == "" {
		return trace.BadParameter("NetworkRestrictions missing Kind field")
	}
	if r.Version == "" {
		r.Version = V1
	}
	return nil
}

func (r *NetworkRestrictions) GetKind() string                       { return r.Kind }
func (r *NetworkRestrictions) GetSubKind() string                    { return r.SubKind }
func (r *NetworkRestrictions) SetSubKind(sk string)                  { r.SubKind = sk }
func (r *NetworkRestrictions) GetVersion() string                    { return r.Version }
func (r *NetworkRestrictions) GetMetadata() Metadata                 { return r.Metadata }
func (r *NetworkRestrictions) GetName() string                       { return r.Metadata.GetName() }
func (r *NetworkRestrictions) SetName(n string)                      { r.Metadata.SetName(n) }
func (r *NetworkRestrictions) GetResourceID() int64                  { return r.Metadata.ID }
func (r *NetworkRestrictions) SetResourceID(id int64)                { r.Metadata.SetID(id) }
func (r *NetworkRestrictions) Expiry() time.Time                     { return r.Metadata.Expiry() }
func (r *NetworkRestrictions) SetExpiry(exp time.Time)               { r.Metadata.SetExpiry(exp) }
