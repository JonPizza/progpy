class Kiss99:
    # https://en.wikipedia.org/wiki/KISS_(algorithm)
    def __init__(self, z, w, jst, jcong):
        self.z = z
        self.w = w 
        self.jst = jst 
        self.jcong = jcong
    
    def next_int(self):
        self.z = 36969 * (self.z & 65535) + (self.z >> 16)
        self.w = 18000 * (self.w & 65535) + (self.w >> 16)
        mwc = ((self.z << 16) + self.w)
        self.jsr ^= (self.jsr << 17)
        self.jsr ^= (self.jsr >> 13)
        self.jsr ^= (self.jsr << 5)
        self.jcong = 69069 * self.jcong + 1234567
        return ((mwc ^ self.jcong) + self.jsr)