package back_maxwell_rangeproof

import (
	"crypto/rand"
	"errors"
	"math/big"
)

type SchnorrSignature struct {
	R ECPoint
	S *big.Int
}

func SignSchnorr(prv *big.Int, publicKey ECPoint, m *big.Int) (SchnorrSignature, error) {
	k, err := rand.Int(rand.Reader, Curve.Params().N)
	if err != nil {
		return SchnorrSignature{}, err
	}

	x, y := Curve.ScalarBaseMult(k.Bytes())
	hash := Hash(m.Bytes(), publicKey.X.Bytes(), publicKey.Y.Bytes())
	s := add(k, minus(mul(hash, prv)))

	return SchnorrSignature{
		R: ECPoint{x, y},
		S: s,
	}, nil
}

func VerifySchnorr(sig SchnorrSignature, publicKey ECPoint, m *big.Int) error {
	hash := Hash(m.Bytes(), publicKey.X.Bytes(), publicKey.Y.Bytes())
	x1, y1 := Curve.ScalarMult(publicKey.X, publicKey.Y, minus(hash).Bytes())
	x1, y1 = Curve.Add(x1, y1, sig.R.X, sig.R.Y)

	x2, y2 := Curve.ScalarBaseMult(sig.S.Bytes())

	if x1.Cmp(x2) != 0 || y1.Cmp(y2) != 0 {
		return errors.New("verification failed")
	}

	return nil
}
