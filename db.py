from dotenv import load_dotenv
import pymysql
import os


load_dotenv(dotenv_path="security.env") #Loads environment variables from .env
def get_db_connection():
    return pymysql.connect(
        host=os.environ.get("DB_HOST"),
        user=os.environ.get("DB_USER"),
        password=os.environ.get("DB_PASSWORD"),
        database=os.environ.get("DB_NAME"),
        port=int(os.environ.get("DB_PORT")),
        cursorclass=pymysql.cursors.DictCursor,
        ssl={'ssl': {}}  #Uses default SSL context, security protocol that creates an encrypted 
        # link between a web server and a web browser
)