from hashlib import sha1
import requests
import hashlib
import sys

class Hash:
    def request_api_data(self,query_char):
        url = 'https://api.pwnedpasswords.com/range/' + query_char
        self.get_request = requests.get(url)                                        
        if self.get_request.status_code != 200:
            raise RuntimeError(f'Error fetching {self.get_request.status_code}: Please check your API and try again')   
        return self.get_request
    
    def hash_function(self,word):
        sha1_password = hashlib.sha1(word.encode('utf-8')).hexdigest().upper()
        first5, tail = sha1_password[:5], sha1_password[5:]
        response = self.request_api_data(first5)
        return self.get_password_leaks_count(response,tail)
    
class Main(Hash):
    def get_password_leaks_count(self,hashes, hash_to_check):
        hashes = (line.split(':') for line in hashes.text.splitlines())
        for hash, count in hashes:
            if hash == hash_to_check:
                return count
        return 0

    def read_passwords(self,filename):
        with open(filename,'r') as file:
            password = file.read().splitlines()
        for i in password:
            count = self.hash_function(i)
            if count:
                print(f'{i} was hacked {count} times. You should probably change your password')
            else:
                print(f'{i} is safe. Carry on!')

if __name__=="__main__":
    obj = Main()
    obj.read_passwords(sys.argv[1])
    sys.exit(0)
