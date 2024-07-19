import requests
import hashlib
import sys


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'error fetching: {res.status_code}, check the api and try again')
    return res


def check_pwned_api(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1_password[:5], sha1_password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks(response, tail)


def get_password_leaks(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def main(args):
    for password in args:
        count = check_pwned_api(password)
        if count:
            print(f'"{password}" was found {count} times. You should probably change your password!')
        else:
            print(f'"{password}" was not found. Carry on!')
    return '---------------------------------ALL TASKS COMPLETED----------------------------------------'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
