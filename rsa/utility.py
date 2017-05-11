#! usr/bin/env python2.7

# Utilities
# From wikipedia's javascript implementation
def modular_multiplicative_inverse(a, n):
	# Set up variables
	t = 0
	nt = 1
	r = n
	n = abs(n)
	if a < 0: 
		a = n - (-a % n)
	nr = a % n
	while nr != 0:
		quot = (r/nr)
		nt, t = t - quot*nt, nt
		nr, r = r - quot*nr, nr
	if r > 1: return -1
	if t < 0: t += n
	return t

# generates a random prime
def random_prime(min_val, max_val):
	p = 1
	while not is_prime(p):
		p = int(math.floor(random.random() * ((max_val - 1) - min_val + 1)))
		p += min_val
	return p

def is_prime(num):
	if num == 2:
		return True
	if num < 2 or num % 2 == 0:
		return False
	# For all odd numbers from 3 to sqrt(num)
	for n in xrange(3, int(num**0.5)+2, 2):
		if num % n == 0:
			return False
	return True

def gcd(a, b):
	while b != 0:
		a, b = b, a % b
	return a