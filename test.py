import json

if __name__ == '__main__':
    dic = {'username': "alice", 'id': 3}
    ret = json.dumps(dic)
    print(ret)