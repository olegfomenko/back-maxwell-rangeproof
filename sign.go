package back_maxwell_rangeproof

import (
	"bytes"
	"crypto/rand"
	"errors"
	"math/big"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
)

type Signature struct {
	R *bn256.G1
	U *big.Int
	V *big.Int
	M *big.Int
}

func Sign(r *big.Int, a *big.Int, m *big.Int, C *bn256.G1) (Signature, error) {
	k1, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		return Signature{}, err
	}

	k2, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		return Signature{}, err
	}

	R := PedersenCommitment(k2, k1)

	e := Hash(hashPoints(R, C).Bytes(), m.Bytes())

	u := add(k1, mul(e, r))
	v := add(k2, mul(e, a))

	return Signature{R, u, v, m}, nil
}

func Verify(signature Signature, C *bn256.G1) error {
	//TODO one hash
	e := Hash(hashPoints(signature.R, C).Bytes(), signature.M.Bytes())

	c := PedersenCommitment(signature.V, signature.U)

	p := ScalarMul(C, e)
	p = Add(p, signature.R)

	if !bytes.Equal(p.Marshal(), c.Marshal()) {
		return errors.New("verification failed")
	}

	return nil
}
