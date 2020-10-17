from datetime import datetime
import dataset

db = dataset.connect('sqlite:///testdb.db')  # 'mssql+pyodbc://server/database'
usertoken_table = db['UserTokens']

def create_db():
    data = [
        dict(UID='12345',
             User=r'BLAHBLAHBLAH\testuser',
             Machine='Win10',
             NetAddress='192.168.1.10',
             Timestamp=datetime.strptime('2020-10-13 9:00:01 +01:00', '%Y-%m-%d %H:%M:%S %z'),
        ),
        dict(UID='a2345',
             User=r'BLAHBLAHBLAH\testuser',
             Machine='Win10',
             NetAddress='192.168.1.10',
             Timestamp=datetime.strptime('2020-10-12 9:00:01 +01:00', '%Y-%m-%d %H:%M:%S %z'),
             ),
    ]
    usertoken_table.delete()
    usertoken_table.insert_many(data)





