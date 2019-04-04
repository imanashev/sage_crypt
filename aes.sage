class AES:
    def __init__(self):
        self.sbox = (
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        )

        self.inv_sbox = (
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
        )

        self.rcon = (
            (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36),
            (0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
            (0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
            (0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        )

        self.nb = 4  # column count
        self.nk = 4  # key len in 32-bit words
        self.nr = 10  # round count

    def encrypt_block(self, input, key):
            self.__fill_state(input)
            self.__key_expansion(key)
            self.__add_round_key()

            for round in range(1, self.nr):
                self.__sub_bytes()
                self.__shift_row()
                self.__mix_columns()
                self.__add_round_key(round)

            # last round
            self.__sub_bytes()
            self.__shift_row()
            self.__add_round_key(round + 1)

            return self.__beautify_out()

    def decrypt_block(self, input, key):
        self.__fill_state(input)
        self.__key_expansion(key)
        self.__add_round_key(self.nr)

        for round in range(self.nr - 1, 0, -1):
            self.__shift_row(inv=True)
            self.__sub_bytes(inv=True)
            self.__add_round_key(round)
            self.__mix_columns(inv=True)

        # last round
        round -= 1
        self.__shift_row(inv=True)
        self.__sub_bytes(inv=True)
        self.__add_round_key(round)

        return self.__beautify_out()        

    def __fill_state(self, input):
        self.state = [[] for j in range(4)]
        for r in range(4):
            for c in range(self.nb):
                self.state[r].append(input[r + 4 * c])

    def __beautify_out(self):
        output = [None] * 4 * self.nb
        for r in range(4):
            for c in range(self.nb):
                output[r + 4 * c] = self.state[r][c]
        return output

    def __add_round_key(self, round=0):
        # print("add round key")

        for col in range(self.nk):
            shift = self.nb * round + col
            for row in range(4):
                self.state[row][col] = (
                    int(self.state[row][col]).__xor__(
                    int(self.key_schedule[row][shift]))
                )

    def __key_expansion(self, key):
        # print("key_expansion")
    
        if len(key) < 4 * self.nk:
            for i in range(4 * self.nk - len(key)):
                key.append(0x01)

        self.key_schedule = [[] for j in range(4)]
        for r in range(4):
            for c in range(self.nk):
                self.key_schedule[r].append(key[r + 4 * c])

        for col in range(self.nk, self.nb * (self.nr + 1)):
            if col % self.nk == 0:
                tmp = [self.key_schedule[row][col - 1] for row in range(1, 4)]
                tmp.append(self.key_schedule[0][col - 1])

                for j in range(len(tmp)):
                    sbox_row = tmp[j] // 0x10
                    sbox_col = tmp[j] % 0x10
                    tmp[j] = self.sbox[16 * sbox_row + sbox_col]

                for row in range(4):
                    # that looks awful
                    self.key_schedule[row].append(
                        int(self.key_schedule[row][col - 4]).__xor__(
                        int(tmp[row]).__xor__(
                        int(self.rcon[row][int(col / self.nk - 1)])
                    )))
            else:
                for row in range(4):
                    self.key_schedule[row].append(
                        int(self.key_schedule[row][col - 4]).__xor__(
                        int(self.key_schedule[row][col - 1])
                    ))

    def __sub_bytes(self, inv=False):
        # print("sub_bytes")

        if inv == False:  # encrypt
            box = self.sbox
        else:  # decrypt
            box = self.inv_sbox

        for i in range(len(self.state)):
            for j in range(len(self.state[i])):
                row = self.state[i][j] // 0x10
                col = self.state[i][j] % 0x10

                self.state[i][j] = box[16 * row + col]

    def __mix_columns(self, inv=False):
        # print("mix_columns")
        for i in range(self.nb):
            if inv == False:  # encryption
                s0 = self.__mul_by_02(self.state[0][i]).__xor__(self.__mul_by_03(self.state[1][i]).__xor__(                 self.state[2][i].__xor__(                  self.state[3][i])))
                s1 =                  self.state[0][i].__xor__( self.__mul_by_02(self.state[1][i]).__xor__(self.__mul_by_03(self.state[2][i]).__xor__(                 self.state[3][i])))
                s2 =                  self.state[0][i].__xor__(                  self.state[1][i].__xor__( self.__mul_by_02(self.state[2][i]).__xor__(self.__mul_by_03(self.state[3][i]))))
                s3 = self.__mul_by_03(self.state[0][i]).__xor__(                 self.state[1][i].__xor__(                  self.state[2][i].__xor__( self.__mul_by_02(self.state[3][i]))))
            else:  # decryption
                s0  = self.__mul_by_0e(self.state[0][i]).__xor__(self.__mul_by_0b(self.state[1][i]).__xor__(self.__mul_by_0d(self.state[2][i]).__xor__(self.__mul_by_09(self.state[3][i]))))
                s1  = self.__mul_by_09(self.state[0][i]).__xor__(self.__mul_by_0e(self.state[1][i]).__xor__(self.__mul_by_0b(self.state[2][i]).__xor__(self.__mul_by_0d(self.state[3][i]))))
                s2  = self.__mul_by_0d(self.state[0][i]).__xor__(self.__mul_by_09(self.state[1][i]).__xor__(self.__mul_by_0e(self.state[2][i]).__xor__(self.__mul_by_0b(self.state[3][i]))))
                s3  = self.__mul_by_0b(self.state[0][i]).__xor__(self.__mul_by_0d(self.state[1][i]).__xor__(self.__mul_by_09(self.state[2][i]).__xor__(self.__mul_by_0e(self.state[3][i]))))
            
            self.state[0][i] = s0
            self.state[1][i] = s1
            self.state[2][i] = s2
            self.state[3][i] = s3

    def __shift_row(self, inv=False):
        # print("shift_row")
        for i in range(1, self.nb):
            if inv == False:  # encrypt
                self.__shift_left(i, i)
            else:  # decrypt
                self.__shift_right(i, i)

    def __shift_left(self, state_raw, count):
        # temp = self.state[state_raw][count:]
        # temp = temp + self.state[state_raw][:count]
        # self.state[state_raw] = temp

        for i in range(count):
            temp = self.state[state_raw][1:]
            temp.append(self.state[state_raw][0])
            self.state[state_raw] = temp

    def __shift_right(self, state_raw, count):
        # temp = self.state[state_raw][:-count]
        # temp = [self.state[state_raw][-count]] + temp
        # self.state[state_raw] = temp

        for i in range(count):
            tmp = self.state[state_raw][:-1]
            tmp.insert(0, self.state[state_raw][-1])
            self.state[state_raw] = tmp

    def __mul_by_02(self, num):
        if num < 0x80:
            res = num << 1
        else:
            res = (num << 1).__xor__(int(0x1b))

        return res % 0x100

    def __mul_by_03(self, num):
        return self.__mul_by_02(num).__xor__(num)

    def __mul_by_09(self, num):
        return self.__mul_by_02(self.__mul_by_02(self.__mul_by_02(num))).__xor__(num)

    def __mul_by_0b(self, num):
        return self.__mul_by_02(self.__mul_by_02(self.__mul_by_02(num))).__xor__(self.__mul_by_02(num).__xor__(num))

    def __mul_by_0d(self, num):
        return self.__mul_by_02(self.__mul_by_02(self.__mul_by_02(num))).__xor__(self.__mul_by_02(self.__mul_by_02(num)).__xor__(num))

    def __mul_by_0e(self, num):
        return self.__mul_by_02(self.__mul_by_02(self.__mul_by_02(num))).__xor__(self.__mul_by_02(self.__mul_by_02(num)).__xor__(self.__mul_by_02(num)))

    
    def __debug(self):
        print("=============================")
        print("State: {}".format(self.state))
        print("Key_schedule: {}".format(self.key_schedule))


key   = "ManashevIldar997"
input = "Hello, sage/aes!"

print("Input: {}".format(input))
print("Key: {}".format(key))

input = [ord(char) for char in input]
key = [ord(char) for char in key]

print("Plain:     {}".format(input))

aes = AES()
encrypted = aes.encrypt_block(input, key)
print("Encrypted: {}".format(encrypted))

decrypted = aes.decrypt_block(encrypted, key)
print("Decrypted: {}".format(decrypted))
