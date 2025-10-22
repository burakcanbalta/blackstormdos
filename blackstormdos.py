import hashlib
import joblib
import zlib
import binascii
import os
import sys
import base64
import threading
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
            'BASE64': lambda x: base64.b64encode(x.encode()).decode(),
            'BASE32': lambda x: base64.b32encode(x.encode()).decode(),
            'BASE16': lambda x: base64.b16encode(x.encode()).decode(),
            'BASE85': lambda x: base64.b85encode(x.encode()).decode(),
            'ASCII85': lambda x: base64.a85encode(x.encode()).decode()
        }
        
        self.encoding_algorithms = {
            'BASE64': lambda x: base64.b64encode(x.encode()).decode(),
            'BASE32': lambda x: base64.b32encode(x.encode()).decode(),
            'BASE16': lambda x: base64.b16encode(x.encode()).decode(),
            'BASE85': lambda x: base64.b85encode(x.encode()).decode(),
            'ASCII85': lambda x: base64.a85encode(x.encode()).decode(),
            'URL_BASE64': lambda x: base64.urlsafe_b64encode(x.encode()).decode(),
            'BASE64_DECODE': lambda x: base64.b64decode(x).decode(),
            'BASE32_DECODE': lambda x: base64.b32decode(x).decode(),
            'BASE16_DECODE': lambda x: base64.b16decode(x).decode()
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
        hash_str_clean = hash_str.strip()
        hash_length = len(hash_str_clean)
        
        if self.is_base64(hash_str_clean):
            return ['BASE64', 'URL_BASE64', 'BASE64_DECODE']
        elif self.is_base32(hash_str_clean):
            return ['BASE32', 'BASE32_DECODE']
        elif self.is_base16(hash_str_clean):
            return ['BASE16', 'BASE16_DECODE']
        elif self.is_base85(hash_str_clean):
            return ['BASE85', 'ASCII85']
        
        hash_patterns = {
            32: ['MD5', 'NTLM'],
            40: ['SHA1'],
            56: ['SHA224', 'SHA3_224'],
            64: ['SHA256', 'SHA3_256', 'BLAKE2s'],
            96: ['SHA384', 'SHA3_384'],
            128: ['SHA512', 'SHA3_512', 'BLAKE2b'],
            8: ['Adler32', 'CRC32']
        }
        
        return hash_patterns.get(hash_length, ['Unknown'])

    def is_base64(self, s):
        try:
            if len(s) % 4 == 0:
                base64.b64decode(s, validate=True)
                return True
        except:
            pass
        return False

    def is_base32(self, s):
        try:
            base64.b32decode(s, validate=True)
            return True
        except:
            pass
        return False

    def is_base16(self, s):
        try:
            base64.b16decode(s, validate=True)
            return True
        except:
            pass
        return False

    def is_base85(self, s):
        try:
            base64.b85decode(s, validate=True)
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
        
        print(f"Trying algorithm: {hash_type}")
        
        if hash_type in self.hash_algorithms:
            hash_func = self.hash_algorithms[hash_type]
        elif hash_type in self.encoding_algorithms:
            hash_func = self.encoding_algorithms[hash_type]
        else:
            print(f"Unsupported algorithm: {hash_type}")
            return None

        found_password = None
        line_count = 0

        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as file:
                for word in file:
                    word = word.strip()
                    if not word:
                        continue
                    
                    line_count += 1
                    try:
                        if hash_type.endswith('_DECODE'):
                            try:
                                decoded = hash_func(word)
                                if decoded == hash_input:
                                    found_password = word
                                    print(f"Encoding match found: {word}")
                                    break
                            except:
                                continue
                        else:
                            hashed = hash_func(word)
                            if hashed == hash_input:
                                found_password = word
                                print(f"Hash match found: {word}")
                                break
                    except Exception as e:
                        continue
                    
                    if line_count % 10000 == 0:
                        print(f"Processed {line_count} passwords...")
                        
        except FileNotFoundError:
            print("Wordlist file not found")
            return None
        except Exception as e:
            print(f"Error reading wordlist: {e}")
            return None

        return found_password

    def crack_with_multiple_types(self, hash_input, wordlist_path):
        possible_types = self.detect_hash_type(hash_input)
        
        print(f"Detected possible algorithms: {', '.join(possible_types)}")
        
        for hash_type in possible_types:
            result = self.crack_single_hash(hash_input, wordlist_path, hash_type)
            if result:
                return result, hash_type
        return None, None

    def crack_with_threads(self, hash_input, wordlist_path, num_threads=4):
        found_password = None
        hash_type = self.ai_predict_hash_type(hash_input)
        
        if hash_type not in self.hash_algorithms and hash_type not in self.encoding_algorithms:
            return None

        if hash_type in self.hash_algorithms:
            hash_func = self.hash_algorithms[hash_type]
        else:
            hash_func = self.encoding_algorithms[hash_type]

        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as file:
                passwords = [line.strip() for line in file if line.strip()]
        except:
            return None

        def check_password(password):
            try:
                if hash_type.endswith('_DECODE'):
                    try:
                        decoded = hash_func(password)
                        return password if decoded == hash_input else None
                    except:
                        return None
                else:
                    hashed = hash_func(password)
                    return password if hashed == hash_input else None
            except:
                return None

        print(f"Starting multi-threaded cracking with {num_threads} threads...")
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = {executor.submit(check_password, pwd): pwd for pwd in passwords}
            
            completed = 0
            total = len(passwords)
            
            for future in as_completed(futures):
                completed += 1
                result = future.result()
                if result:
                    found_password = result
                    executor.shutdown(wait=False)
                    break
                    
                if completed % 10000 == 0:
                    print(f"Progress: {completed}/{total} ({completed/total*100:.1f}%)")

        return found_password

    def encode_text(self, text, encoding_type):
        if encoding_type in self.encoding_algorithms:
            try:
                return self.encoding_algorithms[encoding_type](text)
            except Exception as e:
                return f"Encoding error: {e}"
        return "Unsupported encoding type"

    def decode_text(self, encoded_text, encoding_type):
        decode_map = {
            'BASE64': lambda x: base64.b64decode(x).decode(),
            'BASE32': lambda x: base64.b32decode(x).decode(),
            'BASE16': lambda x: base64.b16decode(x).decode(),
            'BASE85': lambda x: base64.b85decode(x).decode(),
            'ASCII85': lambda x: base64.a85decode(x).decode(),
            'URL_BASE64': lambda x: base64.urlsafe_b64decode(x).decode()
        }
        
        if encoding_type in decode_map:
            try:
                return decode_map[encoding_type](encoded_text)
            except Exception as e:
                return f"Decoding error: {e}"
        return "Unsupported decoding type"

def main():
    print("🚀 Advanced Hash & Encoding Cracker")
    print("=" * 60)
    
    cracker = AdvancedHashCracker()
    
    print("\n1. Crack Hash/Encoding")
    print("2. Encode Text")
    print("3. Decode Text")
    
    choice = input("\nSelect option (1-3): ").strip()
    
    if choice == "1":
        hash_input = input("Enter hash/encoded text: ").strip()
        if not hash_input:
            print("No input provided")
            return
        
        wordlist_path = input("Enter wordlist path: ").strip()
        if not wordlist_path or not os.path.exists(wordlist_path):
            print("Invalid wordlist path")
            return
        
        print("\n🔍 Detection Results:")
        print(f"Input length: {len(hash_input)}")
        detected_types = cracker.detect_hash_type(hash_input)
        print(f"Possible algorithms: {', '.join(detected_types)}")
        
        if cracker.model:
            ai_prediction = cracker.ai_predict_hash_type(hash_input)
            print(f"AI prediction: {ai_prediction}")
        
        use_threads = input("\nUse multi-threading? (y/n): ").strip().lower() == 'y'
        
        print("\n🎯 Starting crack process...")
        
        if use_threads:
            result = cracker.crack_with_threads(hash_input, wordlist_path)
            hash_type = cracker.ai_predict_hash_type(hash_input)
        else:
            result, hash_type = cracker.crack_with_multiple_types(hash_input, wordlist_path)
        
        if result:
            print(f"\n✅ SUCCESS! Password found: {result}")
            print(f"Algorithm: {hash_type}")
        else:
            print("\n❌ Password not found in wordlist")
            
    elif choice == "2":
        text = input("Enter text to encode: ").strip()
        print("\nAvailable encoding types:")
        for algo in cracker.encoding_algorithms.keys():
            if not algo.endswith('_DECODE'):
                print(f"  - {algo}")
        
        encoding_type = input("Select encoding type: ").strip().upper()
        result = cracker.encode_text(text, encoding_type)
        print(f"\nEncoded result: {result}")
        
    elif choice == "3":
        encoded_text = input("Enter encoded text to decode: ").strip()
        print("\nAvailable decoding types:")
        decode_types = ['BASE64', 'BASE32', 'BASE16', 'BASE85', 'ASCII85', 'URL_BASE64']
        for algo in decode_types:
            print(f"  - {algo}")
        
        decoding_type = input("Select decoding type: ").strip().upper()
        result = cracker.decode_text(encoded_text, decoding_type)
        print(f"\nDecoded result: {result}")
        
    else:
        print("Invalid option")

if __name__ == "__main__":
    main()
