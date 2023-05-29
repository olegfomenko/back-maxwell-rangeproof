package back_maxwell_rangeproof

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strconv"

	eth "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

// Curve - the curve we are working on
var Curve = secp256k1.S256()

// Hash function that should return the value in Curve.N field
var Hash func(...[]byte) *big.Int = defaultHash

// defaultHash - default hash function Keccak256
func defaultHash(bytes ...[]byte) *big.Int {
	return new(big.Int).Mod(new(big.Int).SetBytes(eth.Keccak256(bytes...)), Curve.Params().N)
}

type ECPoint struct {
	X, Y *big.Int
}

func (p *ECPoint) String() string {
	return fmt.Sprintf("Elliptic ECPoint[x: %s | y: %s]", p.X.String(), p.Y.String())
}

type Proof struct {
	E0 *big.Int
	C  []ECPoint
	S  []*big.Int
	N  int
}

// PedersenCommitment creates ECPoint with pedersen commitment aH + rG
func PedersenCommitment(H ECPoint, a, r *big.Int) ECPoint {
	aHx, aHy := Curve.ScalarMult(H.X, H.Y, a.Bytes())
	rGx, rGY := Curve.ScalarBaseMult(r.Bytes())

	x, y := Curve.Add(aHx, aHy, rGx, rGY)
	return ECPoint{
		X: x,
		Y: y,
	}
}

// VerifyPedersenCommitment - verifies proof that C commitment commits the value in [0..2^n-1]
func VerifyPedersenCommitment(H ECPoint, C ECPoint, proof Proof) error {
	var R []ECPoint

	for i := 0; i < proof.N; i++ {
		fmt.Println("eCalculating for " + fmt.Sprint(i))

		//calculating ei = Hash(si*G - e0(Ci - 2^i*H))
		x, y := Curve.ScalarBaseMult(proof.S[i].Bytes())
		siG := ECPoint{x, y}

		fmt.Println("Si*G " + x.String() + " " + y.String())

		x, y = Curve.ScalarMult(H.X, H.Y, minus(pow2(i)).Bytes())
		x, y = Curve.Add(proof.C[i].X, proof.C[i].Y, x, y)
		x, y = Curve.ScalarMult(x, y, minus(proof.E0).Bytes())
		x, y = Curve.Add(x, y, siG.X, siG.Y)

		fmt.Println("ei data " + x.String() + " " + y.String())
		ei := hashPoints(ECPoint{x, y})

		fmt.Println("ei " + ei.String())

		x, y = Curve.ScalarMult(proof.C[i].X, proof.C[i].Y, ei.Bytes())
		R = append(R, ECPoint{x, y})
	}

	// eo_ = Hash(Ro||R1||...Rn-1)
	e0_ := hashPoints(R...)

	fmt.Println("E0: " + e0_.String())

	// C = sum(Ci)
	x, y := proof.C[0].X, proof.C[0].Y
	for i := 1; i < proof.N; i++ {
		x, y = Curve.Add(x, y, proof.C[i].X, proof.C[i].Y)
	}

	if e0_.Cmp(proof.E0) != 0 {
		return errors.New("e0 != e0_")
	}

	if C.X.Cmp(x) != 0 || C.Y.Cmp(y) != 0 {
		return errors.New("C != sum(Ci)")
	}

	return nil
}

// CreatePedersenCommitment - creates Pedersen commitment for given val, and
// generates proof that given val lies in [0..2^n-1].
// Returns Proof, generated commitment and private key in case of success generation.
func CreatePedersenCommitment(H ECPoint, val uint64, n int) (Proof, ECPoint, *big.Int, error) {
	// Converting into bit representation
	bitsStr := strconv.FormatUint(val, 2)
	var bits []bool
	for i := len(bitsStr) - 1; i >= 0; i-- {
		bits = append(bits, bitsStr[i] == '1')
	}

	if len(bits) > n {
		return Proof{}, ECPoint{}, nil, errors.New("invalid value: greater then 2^n - 1")
	}

	// Adding leading zeros
	for len(bits) < n {
		bits = append(bits, false)
	}

	prv := big.NewInt(0)
	var r []*big.Int
	var k []*big.Int

	var R []ECPoint
	var C []ECPoint

	for i := 0; i < n; i++ {
		if bits[i] {
			ri, err := rand.Int(rand.Reader, Curve.Params().N)
			if err != nil {
				return Proof{}, ECPoint{}, nil, err
			}
			prv = add(prv, ri)
			r = append(r, ri)

			// Ci = Com(2^i, ri)
			Ci := PedersenCommitment(H, pow2(i), ri)
			C = append(C, Ci)

			ki, err := rand.Int(rand.Reader, Curve.Params().N)
			if err != nil {
				return Proof{}, ECPoint{}, nil, err
			}
			k = append(k, ki)

			// Hash(ki*G)
			x, y := Curve.ScalarBaseMult(ki.Bytes())
			ei := hashPoints(ECPoint{x, y})

			// Ri = Hash(ki*G)*Ci
			x, y = Curve.ScalarMult(Ci.X, Ci.Y, ei.Bytes())
			R = append(R, ECPoint{
				X: x,
				Y: y,
			})
			continue
		}

		ki0, err := rand.Int(rand.Reader, Curve.Params().N)
		if err != nil {
			return Proof{}, ECPoint{}, nil, err
		}
		k = append(k, ki0)

		// Ri = ki0*G
		x, y := Curve.ScalarBaseMult(ki0.Bytes())
		R = append(R, ECPoint{
			X: x,
			Y: y,
		})

		// will be initialized later
		C = append(C, ECPoint{})
		// just placing nil value to be able to get corresponding r[i] for bit == 1 in future
		r = append(r, nil)
	}

	// eo = Hash(Ro||R1||...Rn-1)
	e0 := hashPoints(R...)

	var s []*big.Int

	for i := 0; i < n; i++ {
		if bits[i] {
			// si = ki + e0*r^i
			si := add(k[i], mul(e0, r[i]))
			s = append(s, si)
			continue
		}

		ki, err := rand.Int(rand.Reader, Curve.Params().N)
		if err != nil {
			return Proof{}, ECPoint{}, nil, err
		}

		// ei = Hash(ki*G + e0*2^i*H)
		ei := hashPoints(PedersenCommitment(H, mul(e0, pow2(i)), ki))

		// Ci = Ri /ei = (ki0/ei)*G
		ei_inverse := new(big.Int).ModInverse(ei, Curve.Params().N)
		x, y := Curve.ScalarMult(R[i].X, R[i].Y, ei_inverse.Bytes())
		C[i] = ECPoint{x, y}

		prv = add(prv, mul(k[i], ei_inverse))

		// si = ki + (ki0 * e0)/ei
		si := add(ki, mul(mul(k[i], e0), ei_inverse))
		s = append(s, si)
	}

	x, y := C[0].X, C[0].Y
	for i := 1; i < n; i++ {
		x, y = Curve.Add(x, y, C[i].X, C[i].Y)
	}

	return Proof{
			E0: e0,
			C:  C,
			S:  s,
			N:  n,
		},
		ECPoint{x, y},
		prv,
		nil
}

func add(x *big.Int, y *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Add(x, y), Curve.Params().N)
}

func mul(x *big.Int, y *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Mul(x, y), Curve.Params().N)
}

func pow2(i int) *big.Int {
	return new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(i)), Curve.Params().N)
}

func minus(val *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Mul(val, big.NewInt(-1)), Curve.Params().N)
}

func hashPoints(points ...ECPoint) *big.Int {
	var data [][]byte
	for _, p := range points {
		data = append(data, p.X.Bytes())
		data = append(data, p.Y.Bytes())
	}

	return Hash(data...)
}
