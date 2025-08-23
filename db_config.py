import os
from dotenv import load_dotenv
import pymysql

load_dotenv()    # .env 파일에서 환경변수 로드

def get_connection():
    return pymysql.connect(
        host='localhost',
        user=os.getenv("MYSQL_USER"),
        password=os.getenv("MYSQL_PASSWORD"),
        database=os.getenv("MYSQL_DB"),
        cursorclass=pymysql.cursors.DictCursor
    )

def get_db_connection():
    return get_connection()
