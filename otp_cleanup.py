from dotenv import load_dotenv
import os
from db import get_db_connection
from datetime import datetime, timedelta
import time

load_dotenv(dotenv_path="security.env")

def revoke_expired_otps_and_ban():
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # Find accounts with expired OTP verification (older than 1 day)
            cur.execute("""
                SELECT id FROM account
                WHERE otp_verified = 1 AND otp_verified_at < NOW() - INTERVAL 1 DAY
                        AND online = 0
            """)
            expired_accounts = cur.fetchall()

            for account in expired_accounts:
                account_id = account['id']

                # Revoke OTP verification
                cur.execute("""
                    UPDATE account
                    SET otp_verified = 0
                    WHERE id = %s
                """, (account_id,))

                # Check if already banned
                cur.execute("""
                    SELECT * FROM account_banned
                    WHERE id = %s AND active = 1
                """, (account_id,))
                already_banned = cur.fetchone()

                if not already_banned:
                    ban_timestamp = 0
                    cur.execute("""
                        INSERT INTO account_banned (id, bandate, unbandate, bannedby, banreason, active)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (
                        account_id,
                        ban_timestamp,
                        ban_timestamp,
                        'Apathy',
                        'unverified',
                        1
                    ))

            conn.commit()
            print(f"{len(expired_accounts)} accounts unverified and banned if not already.")
    finally:
        conn.close()

if __name__ == "__main__":
    while True:
        revoke_expired_otps_and_ban()
        time.sleep(3600)  # Wait 1 hour before running again