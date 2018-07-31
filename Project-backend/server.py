# -*- coding: UTF-8 -*-

import tornado.ioloop, tornado.web, tornado.template, tornado.httpserver, tornado.escape
import requests, json, datetime, io ,httplib2, os, pymysql, socket, select
import tornado.gen as gen
from lib import auth
from tornado.tcpserver import TCPServer

class authHandler(tornado.web.RequestHandler) :

    def initialize(self, database) :
        self.database = database
        self.cursor = self.database.cursor(pymysql.cursors.DictCursor)

    def post(self) :
        self.write('connected')
    
        
    
def make_app():
    return tornado.web.Application([
        (r"/oauth", authHandler, dict(database=database))
    ])

if __name__ == '__main__':  
    database = pymysql.connect(host='****', port=3306, user='DevOps', password='****', database='Project', charset='utf8')
    app = make_app()
    app.listen(8888)
    tornado.ioloop.IOLoop.current().start()

