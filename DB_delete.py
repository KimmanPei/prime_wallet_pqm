import sqlite3


def delete_session_msg(dbname):
    cmd = "delete from session_msg"
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    cursor.execute(cmd)
    conn.commit()
    conn.close()


def delete_raw_msg(dbname):
    cmd = "delete from rawmsg"
    conn = sqlite3.connect(dbname)
    cursor = conn.cursor()
    cursor.execute(cmd)
    conn.commit()
    conn.close()

if __name__ == '__main__':
    delete_session_msg("Bob.db")