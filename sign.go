package back_maxwell_rangeproof

import (
	"crypto/rand"
	"errors"
	"math/big"
)

type Signature struct {
	R ECPoint
	U *big.Int
	V *big.Int
	M *big.Int
}

func Sign(r *big.Int, a *big.Int, m *big.Int, H, C ECPoint) (Signature, error) {
	k1, err := rand.Int(rand.Reader, Curve.Params().N)
	if err != nil {
		return Signature{}, err
	}

	k2, err := rand.Int(rand.Reader, Curve.Params().N)
	if err != nil {
		return Signature{}, err
	}

	R := PedersenCommitment(H, k2, k1)

	e := Hash(hashPoints(R, C).Bytes(), m.Bytes())

	u := add(k1, mul(e, r))
	v := add(k2, mul(e, a))

	return Signature{R, u, v, m}, nil
}

func Verify(signature Signature, H, C ECPoint) error {
	e := Hash(hashPoints(signature.R, C).Bytes(), signature.M.Bytes())

	c := PedersenCommitment(H, signature.V, signature.U)
	x, y := Curve.ScalarMult(C.X, C.Y, e.Bytes())
	x, y = Curve.Add(x, y, signature.R.X, signature.R.Y)

	if c.X.Cmp(x) != 0 || c.Y.Cmp(y) != 0 {
		return errors.New("verification failed")
	}

	return nil
}
