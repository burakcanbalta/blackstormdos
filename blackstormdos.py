import hashlib
import joblib
import zlib
import binascii
import os
import sys
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed

class AdvancedHashCracker:
    def __init__(self):
        self.hash_algorithms = {
            'MD5': lambda x: hashlib.md5(x.encode()).hexdigest(),
            'SHA1': lambda x: hashlib.sha1(x.encode()).hexdigest(),
            'SHA224': lambda x: hashlib.sha224(x.encode()).hexdigest(),
            'SHA256': lambda x: hashlib.sha256(x.encode()).hexdigest(),
            'SHA384': lambda x: hashlib.sha384(x.encode()).hexdigest(),
            'SHA512': lambda x: hashlib.sha512(x.encode()).hexdigest(),
            'SHA3_224': lambda x: hashlib.sha3_224(x.encode()).hexdigest(),
            'SHA3_256': lambda x: hashlib.sha3_256(x.encode()).hexdigest(),
            'SHA3_384': lambda x: hashlib.sha3_384(x.encode()).hexdigest(),
            'SHA3_512': lambda x: hashlib.sha3_512(x.encode()).hexdigest(),
            'BLAKE2b': lambda x: hashlib.blake2b(x.encode()).hexdigest(),
            'BLAKE2s': lambda x: hashlib.blake2s(x.encode()).hexdigest(),
            'Adler32': lambda x: format(zlib.adler32(x.encode()) & 0xFFFFFFFF, '08x'),
            'CRC32': lambda x: format(binascii.crc32(x.encode()) & 0xFFFFFFFF, '08x'),
            'NTLM': lambda x: hashlib.new('md4', x.encode('utf-16le')).hexdigest(),
            'Base64': lambda x: base64.b64encode(x.encode()).decode(),
            'Base64_URL': lambda x: base64.urlsafe_b64encode(x.encode()).decode(),
            'Base32': lambda x: base64.b32encode(x.encode()).decode(),
            'Base16': lambda x: base64.b16encode(x.encode()).decode(),
            'Base85': lambda x: base64.b85encode(x.encode()).decode()
        }
        
        self.model = None
        self.vectorizer = None
        self.load_ai_models()

    def load_ai_models(self):
        try:
            if os.path.exists('hash_ai_model.pkl') and os.path.exists('vectorizer.pkl'):
                self.model = joblib.load('hash_ai_model.pkl')
                self.vectorizer = joblib.load('vectorizer.pkl')
        except:
            pass

    def detect_hash_type(self, hash_str):
        hash_length = len(hash_str)
        
        hash_patterns = {
            32: ['MD5', 'NTLM'],
            40: ['SHA1'],
            56: ['SHA224', 'SHA3_224'],
            64: ['SHA256', 'SHA3_256', 'BLAKE2s'],
            96: ['SHA384', 'SHA3_384'],
            128: ['SHA512', 'SHA3_512', 'BLAKE2b'],
            8: ['Adler32', 'CRC32']
        }
        
        possible_types = hash_patterns.get(hash_length, ['Unknown'])
        
        # Base64 tespiti için ek kontrol
        if self.is_base64(hash_str):
            if hash_str.endswith('=') or hash_str.endswith('=='):
                possible_types.append('Base64')
            elif '/' in hash_str or '+' in hash_str:
                possible_types.append('Base64')
            else:
                possible_types.append('Base64_URL')
                
        # Base32 tespiti
        if self.is_base32(hash_str):
            possible_types.append('Base32')
            
        # Base16 tespiti
        if self.is_base16(hash_str):
            possible_types.append('Base16')
            
        # Base85 tespiti
        if self.is_base85(hash_str):
            possible_types.append('Base85')
        
        return possible_types

    def is_base64(self, s):
        try:
            # Base64 karakter seti kontrolü
            base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
            if all(c in base64_chars for c in s):
                # Uzunluk kontrolü (4'ün katı olmalı)
                if len(s) % 4 == 0:
                    # Decode denemesi
                    base64.b64decode(s)
                    return True
        except:
            pass
        
        # URL-safe Base64 kontrolü
        try:
            base64_chars_url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            if all(c in base64_chars_url for c in s):
                base64.urlsafe_b64decode(s)
                return True
        except:
            pass
            
        return False

    def is_base32(self, s):
        try:
            base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567="
            if all(c in base32_chars for c in s):
                base64.b32decode(s)
                return True
        except:
            pass
        return False

    def is_base16(self, s):
        try:
            base16_chars = "0123456789ABCDEF"
            if all(c in base16_chars for c in s.upper()):
                base64.b16decode(s.upper())
                return True
        except:
            pass
        return False

    def is_base85(self, s):
        try:
            base85_chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"
            if all(c in base85_chars for c in s):
                base64.b85decode(s)
                return True
        except:
            pass
        return False

    def ai_predict_hash_type(self, hash_str):
        if self.model and self.vectorizer:
            try:
                vec = self.vectorizer.transform([hash_str])
                return self.model.predict(vec)[0]
            except:
                pass
        
        detected = self.detect_hash_type(hash_str)
        return detected[0] if detected else 'Unknown'

    def crack_single_hash(self, hash_input, wordlist_path, hash_type=None):
        if not hash_type:
            hash_type = self.ai_predict_hash_type(hash_input)
        
        print(f"Trying hash type: {hash_type}")
        
        if hash_type not in self.hash_algorithms:
            print(f"Unsupported hash type: {hash_type}")
            return None

        hash_func = self.hash_algorithms[hash_type]
        found_password = None

        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as file:
                for line_num, word in enumerate(file, 1):
                    word = word.strip()
                    if not word:
                        continue
                    
                    try:
                        hashed = hash_func(word)
                        if hashed == hash_input:
                            found_password = word
                            print(f"Match found: {word}")
                            break
                    except Exception as e:
                        continue
                    
                    if line_num % 10000 == 0:
                        print(f"Processed {line_num} passwords...")
                        
        except FileNotFoundError:
            print("Wordlist file not found")
            return None
        except Exception as e:
            print(f"Error reading wordlist: {e}")
            return None

        return found_password

    def crack_with_multiple_types(self, hash_input, wordlist_path):
        possible_types = self.detect_hash_type(hash_input)
        
        print(f"Detected possible hash types: {', '.join(possible_types)}")
        
        for hash_type in possible_types:
            print(f"Trying {hash_type}...")
            result = self.crack_single_hash(hash_input, wordlist_path, hash_type)
            if result:
                return result, hash_type
        return None, None

    def crack_with_threads(self, hash_input, wordlist_path, num_threads=4):
        found_password = None
        hash_type = self.ai_predict_hash_type(hash_input)
        
        if hash_type not in self.hash_algorithms:
            return None

        hash_func = self.hash_algorithms[hash_type]
        
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as file:
                passwords = [line.strip() for line in file if line.strip()]
        except:
            return None

        def check_password(password):
            try:
                hashed = hash_func(password)
                return password if hashed == hash_input else None
            except:
                return None

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = {executor.submit(check_password, pwd): pwd for pwd in passwords}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_password = result
                    executor.shutdown(wait=False)
                    break

        return found_password

    def direct_base64_decode(self, base64_string):
        """Base64 string'ini doğrudan decode etmeye çalışır"""
        try:
            # Standart Base64
            decoded = base64.b64decode(base64_string).decode('utf-8')
            return decoded
        except:
            pass
            
        try:
            # URL-safe Base64
            decoded = base64.urlsafe_b64decode(base64_string).decode('utf-8')
            return decoded
        except:
            pass
            
        return None

def main():
    print("Advanced Hash Cracker with Base64 Support")
    print("=" * 50)
    
    cracker = AdvancedHashCracker()
    
    hash_input = input("Enter hash: ").strip()
    if not hash_input:
        print("No hash provided")
        return
    
    # Base64 doğrudan decode denemesi
    direct_decode = cracker.direct_base64_decode(hash_input)
    if direct_decode:
        print(f"\nDirect Base64 decode successful: {direct_decode}")
        proceed = input("Continue with wordlist cracking? (y/n): ").strip().lower()
        if proceed != 'y':
            return
    
    wordlist_path = input("Enter wordlist path: ").strip()
    if not wordlist_path or not os.path.exists(wordlist_path):
        print("Invalid wordlist path")
        return
    
    print("\nDetection Results:")
    print(f"Hash length: {len(hash_input)}")
    detected_types = cracker.detect_hash_type(hash_input)
    print(f"Possible types: {', '.join(detected_types)}")
    
    if cracker.model:
        ai_prediction = cracker.ai_predict_hash_type(hash_input)
        print(f"AI prediction: {ai_prediction}")
    
    print("\nStarting crack process...")
    
    use_threads = input("Use multi-threading? (y/n): ").strip().lower() == 'y'
    
    if use_threads:
        num_threads = input("Number of threads (default 4): ").strip()
        num_threads = int(num_threads) if num_threads.isdigit() else 4
        result = cracker.crack_with_threads(hash_input, wordlist_path, num_threads)
        hash_type = cracker.ai_predict_hash_type(hash_input)
    else:
        result, hash_type = cracker.crack_with_multiple_types(hash_input, wordlist_path)
    
    if result:
        print(f"\nSuccess! Password found: {result}")
        print(f"Hash type: {hash_type}")
    else:
        print("\nPassword not found in wordlist")

if __name__ == "__main__":
    main()
