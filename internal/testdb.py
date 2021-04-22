from pathlib import Path
from datetime import datetime
import dataset

db_file = Path(__file__).parent / 'testdb.db'
assert db_file.exists()
db = dataset.connect(f'sqlite:///{db_file}')  # 'mssql+pyodbc://server/database'
usertoken_table = db['UserTokens']

def create_db():
    data = [
        dict(UID='12345',
             User=r'BLAHBLAHBLAH\testuser',
             Machine='Win10',
             NetAddress='192.168.1.10',
             Timestamp=datetime.strptime('2021-04-21 11:00:01 +01:00', '%Y-%m-%d %H:%M:%S %z'),
        ),
        dict(UID='a2345',
             User=r'BLAHBLAHBLAH\testuser',
             Machine='Win10',
             NetAddress='192.168.1.10',
             Timestamp=datetime.strptime('2021-04-20 11:20:01 +01:00', '%Y-%m-%d %H:%M:%S %z'),
             ),
    ]
    usertoken_table.delete()
    usertoken_table.insert_many(data)


if __name__ == "__main__":
    create_db()
