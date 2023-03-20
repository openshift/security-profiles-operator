// Code generated by go-swagger; DO NOT EDIT.

//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// InclusionProof inclusion proof
//
// swagger:model InclusionProof
type InclusionProof struct {

	// The checkpoint (signed tree head) that the inclusion proof is based on
	// Required: true
	Checkpoint *string `json:"checkpoint"`

	// A list of hashes required to compute the inclusion proof, sorted in order from leaf to root
	// Required: true
	Hashes []string `json:"hashes"`

	// The index of the entry in the transparency log
	// Required: true
	// Minimum: 0
	LogIndex *int64 `json:"logIndex"`

	// The hash value stored at the root of the merkle tree at the time the proof was generated
	// Required: true
	// Pattern: ^[0-9a-fA-F]{64}$
	RootHash *string `json:"rootHash"`

	// The size of the merkle tree at the time the inclusion proof was generated
	// Required: true
	// Minimum: 1
	TreeSize *int64 `json:"treeSize"`
}

// Validate validates this inclusion proof
func (m *InclusionProof) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCheckpoint(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateHashes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLogIndex(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRootHash(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTreeSize(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *InclusionProof) validateCheckpoint(formats strfmt.Registry) error {

	if err := validate.Required("checkpoint", "body", m.Checkpoint); err != nil {
		return err
	}

	return nil
}

func (m *InclusionProof) validateHashes(formats strfmt.Registry) error {

	if err := validate.Required("hashes", "body", m.Hashes); err != nil {
		return err
	}

	for i := 0; i < len(m.Hashes); i++ {

		if err := validate.Pattern("hashes"+"."+strconv.Itoa(i), "body", m.Hashes[i], `^[0-9a-fA-F]{64}$`); err != nil {
			return err
		}

	}

	return nil
}

func (m *InclusionProof) validateLogIndex(formats strfmt.Registry) error {

	if err := validate.Required("logIndex", "body", m.LogIndex); err != nil {
		return err
	}

	if err := validate.MinimumInt("logIndex", "body", *m.LogIndex, 0, false); err != nil {
		return err
	}

	return nil
}

func (m *InclusionProof) validateRootHash(formats strfmt.Registry) error {

	if err := validate.Required("rootHash", "body", m.RootHash); err != nil {
		return err
	}

	if err := validate.Pattern("rootHash", "body", *m.RootHash, `^[0-9a-fA-F]{64}$`); err != nil {
		return err
	}

	return nil
}

func (m *InclusionProof) validateTreeSize(formats strfmt.Registry) error {

	if err := validate.Required("treeSize", "body", m.TreeSize); err != nil {
		return err
	}

	if err := validate.MinimumInt("treeSize", "body", *m.TreeSize, 1, false); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this inclusion proof based on context it is used
func (m *InclusionProof) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *InclusionProof) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *InclusionProof) UnmarshalBinary(b []byte) error {
	var res InclusionProof
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
