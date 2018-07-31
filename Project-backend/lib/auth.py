import pymysql, hashlib, datetime

'''
{
    'OauthType' : type,
    'Token' : hex,
    'UUID' : 1234556789,
    'Credentials' : {
        'email' : email,
        'password' : password,
    }

    'Value' : {
        'Target' : '...',
        '...' : '...',
        '...' : '...',
    }
}
'''

class User :
    
    def __init__ (self, cursor, OauthAction, uuid=None, token=None, email=None, password=None, credentialsPack=None) : 
        self.cursor = cursor
        self.status = None
        if uuid and token :
            self.updateStatus(uuid, token)
        self.email = email
        self.password = password
        self.credentialspack = credentialsPack
        self.OauthAction = OauthAction
        self.Oauth = self.actionFactory(OauthAction)

    def updateStatus(self, uuid, token) :
        # Give full user access when uuid and token has been submitted correctly. (Save in local storage.)
        # Callback when these scenario has been got through successfully - 
        # 1. SignIn then launch the app.
        # 2. SignOut then -->[SignUp(SignUp -> SignIn), SignIn(SignOut -> SignIn)]
        user = self.cursor.execute('''SELECT * FROM user WHERE token=%s'''%self.uuid)
        if user != 0 and user.fetchone()['token'] == token :
            self.token = token
            self.uuid = user.fetchone()['uuid']
            self.information = user.fetchone()
            self.status = True
        else :
            self.status = False
    
    def checkDecorator(func) :
        # Check privileges when action requires authorization.
        def accessCheck(*args, **kwargs) :
            if self.status :
                return func(*args, **kwargs)
            else :
                return 
        return accessCheck
            

    def actionFactory(self, OauthAction) :
        try :
            return {
                'UniCheck' : self.UniCheck(self.credentialspack['Target'], self.credentialspack),
                'emailOauth' : self.emailOauth(self.OauthAction, self.email, self.password),
                'facebookOauth' : self.facebookOauth(kwarg[''])
            }[OauthAction]
        except :
            return rStruct(Bool=False, Target='Oauth', Message='Server Internal Error.')

    def UniCheck(target, credentialspack) :
        #Target should always equal to field name of credentialspack and column name of user database.
        if not target or not credentialspack :
            return rStruct(Bool=False, Target='UniCheck' Message='No Data Provided.')
        elif target not in [ x['Field'] for x in self.cursor.execute('''SHOW COLUMNS FROM user''').fetchall()]:
            return rStruct(Bool=False, Target='UniCheck' Message='Wrong Target Value.')
        else :    
            value = credentialspack[target]
            check = self.cursor.execute('''SELECT * from user WHERE %s = %s'''%(target, value))
            if check != 0 :
                return rStruct(Bool=False,Target=target, Message='Value Has Been Already Created.')
            else :
                return rStruct(Bool=True,Target=target, Message='Value Is Available For Submit.')
    
    def emailOauth(OauthType, email, password) :
        try :
            OauthType = OauthType.split['_'][1]
        except :
            return rStruct(Bool=False,Target='Oauth', Message='No Oauth Action Has Been Provided Behind "Under-Case".')
        if not email and not password :
            return rStruct(Bool=False, Target='Oauth' Message='No Data Provided.')
        else :
            if OauthType == 'SignUp' :
                # SignUp process start here.
                flag = self.UniCheck(email, {'email' : email})['Bool']
                saveField = self.credentialspack
                saveField.pop('Target')
                table = self.cursor.execute('''SHOW COLUMNS FROM user''').fetchall()
                if flag['Bool'] and self.credentialspack and len(set(saveField) - set([x['Field'] for x in table])) == 0:
                    for field in table:
                        if field['Null'] == 'No' and field['Field'] not in saveField :
                            return rStruct(Bool=True,Target='SignUp', Message='No Required Field Included : %s.'%field['Field'])
                    saveKey = str(tuple(saveField.keys()))
                    saveValue = str(tuple(saveField.values()))
                    self.cursor.execute('''INSERT INTO user %s VALUES %s'''%(saveKey.replace("'",""), saveValue))
                    self.cursor.execute('''COMMIT''')
                    self.emailOauth('emailOauth_SignIn', email, password)
                else :
                    return flag
            elif OauthType == 'SignIn' :
                # SignIn process start here.
                if self.status :
                    # If token has been submitted correctly then return information directly.
                    return eturn rStruct(Bool=True, Target='SignIn', Message='', Data=self.information)
                else :
                    # Require email and password for login verification.
                    if not self.email and self.password :
                        return rStruct(Bool=False, Target='SignIn', Message='Email or Password Required For SignIn.')
                    select = self.cursor.execute('''SELECT * FROM user WHERE email=%s'''%self.email)
                    if select = 0 :
                        return rStruct(Bool=False, Target='SignIn', Message='Wrong Email For SignIn.')
                    else :
                        if select.fetchone()['password'] == self.passowrd :
                            return rStruct(Bool=True, Target='SignIn', Message='', Data=select.fetchone())
                        else :
                            return rStruct(Bool=False, Target='SignIn', Message='Wrong Password For SignIn.')
                    
            elif OuathType == 'SignOut' :
                    if self.uuid :
                        self.cursor.execute('''UPDATE user SET token = NULL WHERE uuid = %s'''%self.uuid)
                        return rStruct(Bool=True, Target='SignOut', Message='')
                    else :
                        return rStruct(Bool=False, Target='SignOut', Message='Incomplete Requests Information.')
            else :
                return rStruct(Bool=False,Target='Oauth', Message='OauthType Error.')
            
def rStruct(Bool=False, Target=None, Message=None, Data=None) :
        
    Struct = {
        'Bool' : Bool,
        'Target' : Target,
        'Message' : Message,
        'Data' : Data
    }
    
