package main

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"time"
)

// 10^6
const maxAdditiveElGamal int64 = 10000000

// ElGamal public key
type PublicKey struct {
	// Prime modulus of (Z / pZ)*
	p *big.Int

	// Prime order of subgroup of (Z / pZ)*
	q *big.Int
	// Generator of subgroup
	g *big.Int

	// y = g^x mod p
	y *big.Int
}

func (pub PublicKey) String() string {
	return fmt.Sprintf("(\n\tp = %d\n\tq = %d\n\tg = %d\n\ty = %d\n)\n", pub.p, pub.q, pub.g, pub.y)
}

// ElGamal private key
type PrivateKey struct {
	// Private exponent from (Z / qZ)
	x *big.Int
}

func (priv PrivateKey) String() string {
	return fmt.Sprintf("(\n\tx = %d\n)", priv.x)
}

func AdditiveEncrypt(msg *big.Int, pub PublicKey) (*big.Int, *big.Int, error) {
	h := big.NewInt(0)
	h.Set(pub.g)
	h.Exp(h, msg, pub.p)

	return Encrypt(h, pub)
}

func AdditiveDecrypt(R *big.Int, c *big.Int, pub PublicKey, priv PrivateKey) (*big.Int, error) {
	h, err := Decrypt(R, c, pub, priv)
	if err != nil {
		return big.NewInt(0), err
	}

	// Size limitation on maxAdditiveElGamal will ensure it'll comfortably fit in an int64
	for i := int64(0); i <= maxAdditiveElGamal; i += 1 {
		exponent := big.NewInt(i)
		power := big.NewInt(0)
		power.Exp(pub.g, exponent, pub.p)

		if power.Cmp(h) == 0 {
			return exponent, nil
		}
	}

	return big.NewInt(0), fmt.Errorf("Did not find exponent, input must have been invalid")
}

func Encrypt(msg *big.Int, pub PublicKey) (*big.Int, *big.Int, error) {
	R := big.NewInt(0)
	c := big.NewInt(0)

	// TODO: Ensuer m < q, then map to G
	// if msg.Cmp(pub.q) != -1 {
	// 	return R, c, fmt.Errorf("Cannot encrypt m = %v > q = %v", msg, pub.q)
	// }

	r, err := RandomInt(big.NewInt(0), pub.q)
	if err != nil {
		return R, c, err
	}
	// R = g^r mod p
	R.Exp(pub.g, r, pub.p)

	// c = m * y^r mod p.

	// c = y
	c.Set(pub.y)
	// c = y^r mod p
	c.Exp(c, r, pub.p)
	// c = m * (y^r mod p)
	c.Mul(c, msg)
	// c = (m * y^r) mod p
	c.Mod(c, pub.p)

	return R, c, nil
}

func Decrypt(R *big.Int, c *big.Int, pub PublicKey, priv PrivateKey) (*big.Int, error) {
	msg := big.NewInt(0)

	// m = c / R^x

	// m = R^x
	msg.Exp(R, priv.x, pub.p)
	// m = (R^x)^(-1)
	msg.ModInverse(msg, pub.p)
	// m = c / R^x
	msg.Mul(msg, c)
	msg.Mod(msg, pub.p)

	return msg, nil
}

// Parameters are chosen as per the DSS spec
func Parameters(subgroupBitLength int, groupBitLength int) (PublicKey, PrivateKey, error) {
	pub := PublicKey{}
	priv := PrivateKey{}

	// We start with the subgroup, then calculate the modulus of (Z / pZ)*
	q, err := rand.Prime(rand.Reader, subgroupBitLength)
	if err != nil {
		return pub, priv, err
	}
	pub.q = q

	p := big.NewInt(0)
	for {
		mBitLength := groupBitLength - subgroupBitLength - 1
		m, err := RandomBits(mBitLength)
		if err != nil {
			return pub, priv, err
		}

		// p = m * q + 1
		p.SetBytes(m)
		p.Mul(p, pub.q)
		p.Add(p, big.NewInt(1))

		if p.ProbablyPrime(20) {
			pub.p = p
			break
		}
	}
	pub.p = p

	// And lastly the generator, constructed such that it is cyclic
	// (euclid's theorem) and of order q (as q prime)
	g := big.NewInt(1)
	for {
		// In [2, p) = [2, p-1]
		h, err := RandomInt(big.NewInt(2), p)
		if err != nil {
			return pub, priv, err
		}

		// exponent = (p - 1) / q
		exponent := big.NewInt(0)
		exponent.Sub(pub.p, big.NewInt(1)).Div(exponent, q)

		// g = h^(exponent) mod p
		g.Exp(h, exponent, pub.p)

		if g != big.NewInt(1) {
			pub.g = g
			break
		}
	}

	// Secret exponent x in [1, q)
	x, err := RandomInt(big.NewInt(1), pub.q)
	if err != nil {
		return pub, priv, err
	}
	priv.x = x

	// y = g^x mod p
	y := big.NewInt(0)
	y.Exp(pub.g, x, pub.p)
	pub.y = y

	return pub, priv, nil
}

// Convenience wrapper around rand.Int, supporting a min value.
//
// Returns a value in [min, max)
func RandomInt(min *big.Int, max *big.Int) (*big.Int, error) {
	var max2 big.Int
	max2.Sub(max, min)

	// rand.Int returns in [0, max). We want [min, max)
	x, err := rand.Int(rand.Reader, &max2)
	if err != nil {
		return x, err
	}

	// x is now in [0, max - min)
	x.Add(x, min)
	// And now in [min, max)
	return x, nil
}

// Returns `bitLength` random bits. If not a multiple of 8, the upper bits of
// the first byte will be forced to zero.
func RandomBits(bitLength int) ([]byte, error) {
	// For bit lengths which aren't multiples of eight, this will be more bits
	// than we need - we'll just truncate later.
	byteLength := int(math.Ceil(float64(bitLength) / 8))
	out := make([]byte, byteLength)

	_, err := rand.Read(out)
	if err != nil {
		return out, err
	}

	// If bitLength is not a multiple of 8, zero the superfluous bits of the
	// leading byte.
	if zeroLeadingBits := 8*byteLength - bitLength; zeroLeadingBits != 0 {
		out[0] = out[0] & (0xFF >> zeroLeadingBits)
	}

	return out, nil
}

func main() {
	// qBits := 160
	// pBits := 1024
	qBits := 256
	pBits := 2048

	pub, priv, err := Parameters(qBits, pBits)
	if err != nil {
		panic(err)
	}

	// exponent size => sample count
	// Sample count chosen such that:
	// - We have at least 5, to be statistically relevant
	// - We never go beyond 1000, that will be close enough to the true average
	// - We take about 200s for those classes between the two extremes
	var samples = map[int]int{
		2: 1000, // 0.01s each => 10s
		3: 1000, // 0.1s each => 100s
		4: 200,  // 1s each => 200s
		5: 20,   // 10s each => 200s
		6: 5,    // 100s each => 500s
	}

	// We'll print it in a format suitable for redirection to a CSV and further preprocessing
	fmt.Println("keyid,exponent,duration_ms")
	for exponent, sample_count := range samples {
		results := timeAdditiveDecryptionSamples(sample_count, exponent, pub, priv)
		for _, dur := range results {
			fmt.Printf("\"q=%d,p=%d\",%d,%v\n", qBits, pBits, exponent, dur.Milliseconds())
		}
	}
}

func timeAdditiveDecryptionSamples(count int, log10 int, pub PublicKey, priv PrivateKey) []time.Duration {
	times := make([]time.Duration, 0)

	// We'll want numbers in [1 * 10^x .. 5 * 10^x]
	lower := big.NewInt(int64(math.Pow10(log10)))
	upper := big.NewInt(5 * int64(math.Pow10(log10)))

	for i := 0; i < count; i += 1 {
		a, _ := RandomInt(lower, upper)
		b, _ := RandomInt(lower, upper)

		ra, ca, err := AdditiveEncrypt(a, pub)
		if err != nil {
			fmt.Printf("Error encrypting a: %v\n", err)
		}

		rb, cb, err := AdditiveEncrypt(b, pub)
		if err != nil {
			fmt.Printf("Error encrypting b: %v\n", err)
		}

		rc := big.NewInt(0)
		rc.Mul(ra, rb).Mod(rc, pub.p)

		cc := big.NewInt(0)
		cc.Mul(ca, cb).Mod(cc, pub.p)

		start := time.Now()
		_, err = AdditiveDecrypt(rc, cc, pub, priv)
		times = append(times, time.Since(start))
		if err != nil {
			fmt.Printf("Error decrypting c: %v\n", err)
		}

	}

	return times
}

func test(count int, pub PublicKey, priv PrivateKey) {
	for i := 0; i < count; i += 1 {
		m, err := RandomInt(big.NewInt(1), pub.q)
		if err != nil {
			fmt.Printf("ERROR: Unable to generate random number: %v\n", err)
		}

		R, c, err := Encrypt(m, pub)
		if err != nil {
			fmt.Printf("ERROR: Unable to encrypt number: %v\n", err)
		}

		mRecovered, err := Decrypt(R, c, pub, priv)
		if err != nil {
			fmt.Printf("ERROR: Unable to decrypt number: %v\n", err)
		}

		if m.Cmp(mRecovered) != 0 {
			fmt.Printf("ERROR: Dec(Enc(m)) != m. m = %v, (R, c) = (%v, %v), m' = %v\n", m, R, c, mRecovered)
			fmt.Printf("Pub = %v, Priv = %v\n", pub, priv)
		} else {
			fmt.Printf(".")
		}
	}
}
