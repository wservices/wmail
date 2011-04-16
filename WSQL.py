import MySQLdb

from WConfig import *

class WSQL:
	def __init__(self):
		self.conn = MySQLdb.connect(host=WConfig.MYSQL_HOST, port=WConfig.MYSQL_PORT, user=WConfig.MYSQL_USER, passwd=WConfig.MYSQL_PASSWD, db=WConfig.MYSQL_DB)
		self.cursor = self.conn.cursor()

	def execute(self, query, args=None, result=False):
		self.cursor.execute(query, args)
		if result == True:
			return self.cursor.fetchall()
	
	def __del__(self):
		self.cursor.close()
		self.conn.close()

