//! Python's `random.Random(int)` (MT19937) for the frozen `random-blocks`
//! schedule: the same seed must give the same published order.

const N: usize = 624;
const M: usize = 397;

pub struct Random {
    state: [u32; N],
    index: usize,
}

impl Random {
    /// `random.Random(seed)`: `init_by_array` over the 32-bit words of `|seed|`.
    pub fn new(seed: i64) -> Self {
        let mut magnitude = seed.unsigned_abs();
        let mut key = Vec::new();
        loop {
            key.push(magnitude as u32);
            magnitude >>= 32;
            if magnitude == 0 {
                break;
            }
        }
        let mut random = Self {
            state: [0; N],
            index: N,
        };
        random.init_genrand(19_650_218);
        let (mut i, mut j) = (1usize, 0usize);
        for _ in 0..N.max(key.len()) {
            let previous = random.state[i - 1] ^ (random.state[i - 1] >> 30);
            random.state[i] = (random.state[i] ^ previous.wrapping_mul(1_664_525))
                .wrapping_add(key[j])
                .wrapping_add(j as u32);
            i += 1;
            j += 1;
            if i >= N {
                random.state[0] = random.state[N - 1];
                i = 1;
            }
            if j >= key.len() {
                j = 0;
            }
        }
        for _ in 0..N - 1 {
            let previous = random.state[i - 1] ^ (random.state[i - 1] >> 30);
            random.state[i] =
                (random.state[i] ^ previous.wrapping_mul(1_566_083_941)).wrapping_sub(i as u32);
            i += 1;
            if i >= N {
                random.state[0] = random.state[N - 1];
                i = 1;
            }
        }
        random.state[0] = 0x8000_0000;
        random
    }

    fn init_genrand(&mut self, seed: u32) {
        self.state[0] = seed;
        for i in 1..N {
            let previous = self.state[i - 1] ^ (self.state[i - 1] >> 30);
            self.state[i] = 1_812_433_253u32
                .wrapping_mul(previous)
                .wrapping_add(i as u32);
        }
        self.index = N;
    }

    fn next_u32(&mut self) -> u32 {
        if self.index >= N {
            for k in 0..N {
                let y = (self.state[k] & 0x8000_0000) | (self.state[(k + 1) % N] & 0x7fff_ffff);
                let mag = if y & 1 == 1 { 0x9908_b0df } else { 0 };
                self.state[k] = self.state[(k + M) % N] ^ (y >> 1) ^ mag;
            }
            self.index = 0;
        }
        let mut y = self.state[self.index];
        self.index += 1;
        y ^= y >> 11;
        y ^= (y << 7) & 0x9d2c_5680;
        y ^= (y << 15) & 0xefc6_0000;
        y ^ (y >> 18)
    }

    /// `getrandbits(k)` for `1 <= k <= 32`.
    fn bits(&mut self, k: u32) -> u32 {
        self.next_u32() >> (32 - k)
    }

    /// `_randbelow_with_getrandbits(n)`.
    fn below(&mut self, n: usize) -> usize {
        let k = usize::BITS - n.leading_zeros();
        loop {
            let value = self.bits(k) as usize;
            if value < n {
                return value;
            }
        }
    }

    /// `sample(population, k)` for the small populations used here (the
    /// pool branch: `n <= 21`).
    pub fn sample<T: Clone>(&mut self, population: &[T], k: usize) -> Vec<T> {
        let n = population.len();
        assert!(k <= n && n <= 21, "sample supports small populations only");
        let mut pool = population.to_vec();
        let mut result = Vec::with_capacity(k);
        for i in 0..k {
            let j = self.below(n - i);
            result.push(pool[j].clone());
            pool[j] = pool[n - i - 1].clone();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_python_random() {
        let mut random = Random::new(42);
        assert_eq!(
            [random.next_u32(), random.next_u32(), random.next_u32()],
            [2746317213, 478163327, 107420369]
        );
        let mut random = Random::new((1 << 40) + 7);
        assert_eq!(
            [random.next_u32(), random.next_u32()],
            [2635837658, 3209733218]
        );
        let four = ["stock", "r89", "r94", "candidate"];
        let three = ["stock", "r84", "candidate"];
        for (seed, expected_four, expected_three) in [
            (
                0,
                ["candidate", "r89", "stock", "r94"],
                ["r84", "candidate", "stock"],
            ),
            (
                1,
                ["r89", "r94", "stock", "candidate"],
                ["stock", "candidate", "r84"],
            ),
            (
                20261126,
                ["candidate", "r89", "stock", "r94"],
                ["r84", "candidate", "stock"],
            ),
            (
                -5,
                ["r94", "candidate", "r89", "stock"],
                ["candidate", "r84", "stock"],
            ),
        ] {
            assert_eq!(
                Random::new(seed).sample(&four, 4),
                expected_four,
                "seed {seed}"
            );
            assert_eq!(
                Random::new(seed).sample(&three, 3),
                expected_three,
                "seed {seed}"
            );
        }
        let mut random = Random::new(7);
        let order: Vec<&str> = (0..3).flat_map(|_| random.sample(&three, 3)).collect();
        assert_eq!(
            order,
            [
                "r84",
                "stock",
                "candidate",
                "candidate",
                "stock",
                "r84",
                "candidate",
                "stock",
                "r84"
            ]
        );
    }
}
