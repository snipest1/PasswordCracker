from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from encodings.base64_codec import base64_encode, base64_decode
import random
import csv
import time

# our alphabet is various sizes, because speed of cracking is an issue
alphabet = ["A", "B", "C", "D", "E"]
            #"F", "G", "H", "I", "K"]
               # "L", "M", "N", "O",
               #"P", "Q", "R", "S", "T"]
               #"U", "V", "W", "X", "Y",
               #"Z"]

# create Hash byte string
def hashSha256(bytestring):
    myhash = hashes.SHA256()
    backend = default_backend()
    hasher = hashes.Hash(myhash, backend)
    hasher.update(bytestring)
    digest = hasher.finalize()
    return digest

def createRandomPassword(length):
    created_pw = ""
    for i in range(length):
        #created_pw = created_pw + random.choice(letters)
        created_pw = created_pw + random.choice(alphabet)
    return created_pw

def createDictionary():
    passwords = dict()
    backend = default_backend()

    #letters = ["A", "B", "C", "D", "E"]
    letters = alphabet
    for letter1 in letters:
        for letter2 in letters:
            for letter3 in letters:
                for letter4 in letters:
                    for letter5 in letters:
                        new_password = letter1 + letter2 + letter3 + letter4 + letter5
                        myhash = hashes.SHA256()
                        hasher_sha256 = hashes.Hash(myhash, backend)
                        hasher_sha256.update(new_password.encode())
                        digest = hasher_sha256.finalize()

                        passwords[digest.hex()] = new_password

    for key, value in passwords.items():
        print(key, '->', value)

    with open('dictionary.csv', 'w') as file:
        for key in passwords.keys():
            file.write("%s,%s\n" % (key, passwords[key]))

    return passwords

def searchUsingDictionary(dict_file, random_password):
    # Reading the dictionary
    with open(dict_file) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        line_count = 0
        for row in csv_reader:
            rows = f'{" ".join(row)}'
            # Brute force search
            if random_password in rows:
                print("Found password in dict")
                return

def searchByHashing(random_password_hash):
    letters = alphabet
    for letter1 in letters:
        for letter2 in letters:
            for letter3 in letters:
                for letter4 in letters:
                    for letter5 in letters:
                        new_password = letter1 + letter2 + letter3 + letter4 + letter5
                        new_password_hash = hashSha256(new_password.encode())
                        if new_password_hash == random_pw_hash:
                            print("Found password with hash")
                            return
def reduce2(digest):
    b64_representation = base64_encode(digest)
    new_password = ""
    for m in range(len(b64_representation)):
        one_byte = bytes([b64_representation[m]])
        char = one_byte.decode()
        print("char", char)
        if char.isalpha():
            new_password = char.upper() + new_password
            print("new password", new_password)
            if len(new_password) == 5:
                break
    return new_password

def reduce(digest_hex):
    b64_representation = base64_encode(bytes.fromhex(digest_hex))
    #print("b64 representation", b64_representation)
    #print("b64[0]", b64_representation[0])
    #print("b64[1]", b64_representation[1])
    new_password2 = ""
    for i in range(len(b64_representation[0])):
        #print("byte", byte)
        #print("decode byte", chr(byte))
        decoded_byte = chr(b64_representation[0][i])
        if decoded_byte.isalpha():
            if decoded_byte.upper() in alphabet:
                new_password2 = new_password2 + decoded_byte.upper()
            if len(new_password2) == 5:
                break

    new_password = ""

    generated_password = b64_representation[0][:5]  # First 5 characters
    generated_password = generated_password.decode()
    # print("generated password", generated_password)

    new_password = ""
    for i in range(len(generated_password)):
        new_password = new_password + alphabet[ord(generated_password[i]) % len(alphabet)]

    # print("new password 2", new_password2)
    # print(new_password)
    # for i in range(len(generated_password)):
    #    new_password = new_password + alphabet[ord(generated_password[i]) % len(alphabet)]
    if len(new_password2) != 5:
        print("reduce not to 5")
    return new_password2


def createRainbowTable(percentage):
    possible_passwords = list()

    rainbow_table = list()
    rainbow_dict = dict()

    letters = alphabet
    print("start creating list of passwords")
    epoch = 0
    for letter1 in letters:
        for letter2 in letters:
            for letter3 in letters:
                for letter4 in letters:
                    for letter5 in letters:
                        random_pw = letter1 + letter2 + letter3 + letter4 + letter5
                        possible_passwords.append(letter1 + letter2 + letter3 + letter4 + letter5)
                        if epoch % 10 == 0:
                            start = random_pw
                            current_pw = start
                            for k in range(10):
                                digest = hashSha256(current_pw.encode())
                                current_pw = reduce(digest.hex())
                            end = current_pw
                            rainbow_dict[start] = end
                        epoch = epoch + 1
                        if epoch % 1000 == 0:
                            print(epoch)

    print("done creating list of passwords")
    num_chains = int(len(possible_passwords) * percentage)
    print("number chains", num_chains)

    """
    unused_indices = list()
    for i in range(len(possible_passwords)):
        unused_indices.append(i)

    for j in range(num_chains):
        if j % 1000 == 0:
            print("j", j)
        rand_index = random.choice(unused_indices)
        unused_indices.remove(rand_index)

        random_pw = possible_passwords[rand_index]

        start = random_pw
        current_pw = start
        for k in range(10):
            digest = hashSha256(current_pw.encode())
            current_pw = reduce(digest.hex())
        end = current_pw

        #print("start", start, "end", end)
        #rainbow_table.append([start, end])
        rainbow_dict[start] = end
    """
    with open('rainbow_dictionary.csv', 'w') as file:
        for key in rainbow_dict.keys():
            file.write("%s,%s\n" % (key, rainbow_dict[key]))
    # print(rainbow_table)


def searchRainbowTable(dict_file, password):
    initial_hash = hashSha256(password.encode())
    initial_reduction = reduce(initial_hash.hex())

    current_reduction = initial_reduction
    for i in range(10):
        # current_hash = hashSha256(current_reduction.encode())
        # current_reduction = reduce(current_hash.hex())
        with open(dict_file) as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',')
            line_count = 0
            for row in csv_reader:
                if current_reduction == row[1]:
                    current_value = row[0]
                    current_digest = hashSha256(current_value.encode())
                    current_reduction = reduce(current_digest.hex())
                    prev_value = current_value
                    i = 0
                    #print("initial reduction", initial_reduction)
                    while current_digest != initial_hash:
                        prev_value = current_reduction
                        current_digest = hashSha256(current_reduction.encode())
                        current_reduction = reduce(current_digest.hex())
                        i = i + 1
                        if i == 10:
                            break
                    if current_digest == initial_hash:
                        return prev_value
        current_hash = hashSha256(current_reduction.encode())
        current_reduction = reduce(current_hash.hex())
    return "No Match"


password_dict = createDictionary()
createRainbowTable(.1)

hashSearchTimes = list()
dictSearchTimes = list()
rainbowSearchTimes = list()
totalHashSearchTimes = 0
totalDictSearchTimes = 0
totalRainbowSearchTimes = 0
num_matches = 0
for i in range(100):
    random_pw = createRandomPassword(5)
    random_pw_hash = hashSha256(random_pw.encode())

    start_time1 = time.time()
    searchUsingDictionary('dictionary.csv', random_pw)
    end_time1 = time.time()

    start_time2 = time.time()
    searchByHashing(random_pw_hash)
    end_time2 = time.time()

    start_time3 = time.time()
    found_pw = searchRainbowTable("rainbow_dictionary.csv", random_pw)
    if random_pw == found_pw:
        num_matches = num_matches + 1
    end_time3 = time.time()

    hashSearchTime = end_time2 - start_time2
    dictSearchTime = end_time1 - start_time1
    rainbowSearchTime = end_time3 - start_time3
    dictSearchTimes.append(dictSearchTime)
    hashSearchTimes.append(hashSearchTime)
    rainbowSearchTimes.append(rainbowSearchTime)
    totalHashSearchTimes = totalHashSearchTimes + hashSearchTime
    totalDictSearchTimes = totalDictSearchTimes + dictSearchTime
    totalRainbowSearchTimes = totalRainbowSearchTimes + rainbowSearchTime
    print("Searching with dict", end_time1 - start_time1)
    print("Searching with hash", end_time2 - start_time2)
    print("Searching with rainbow", end_time3 - start_time3)

print("Average dict search time", totalDictSearchTimes/100)
print("Average hash search time", totalHashSearchTimes/100)
print("Average rainbow search time", totalRainbowSearchTimes/100)
print("rainbow accuracy", float(num_matches/100.0))

