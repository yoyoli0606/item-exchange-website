#!/usr/bin/env python
import webapp2
from google.appengine.ext.webapp import template
from google.appengine.ext import ndb
import logging
import os
import os.path

import jinja2

from webapp2_extras import auth
from webapp2_extras import sessions

from webapp2_extras.auth import InvalidAuthIdError
from webapp2_extras.auth import InvalidPasswordError

JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)


def user_required(handler):
  """
    Decorator that checks if there's a user associated with the current session.
    Will also fail if there's no session present.
  """
  def check_login(self, *args, **kwargs):
    auth = self.auth
    if not auth.get_user_by_session():
      self.redirect(self.uri_for('login'), abort=True)
    else:
      return handler(self, *args, **kwargs)

  return check_login

def user_required2(handler):
  """
    Decorator that checks if there's a user associated with the current session.
    Will also fail if there's no session present.
  """
  def check_login(self, *args, **kwargs):
    return handler(self, *args, **kwargs)

  return check_login

class Form(ndb.Model):
    product_name = ndb.StringProperty()
    time=ndb.StringProperty()
    owner = ndb.StringProperty()
    price=ndb.StringProperty()
    phone=ndb.StringProperty()
    description=ndb.StringProperty()
    userId = ndb.IntegerProperty() 
    imageId=ndb.IntegerProperty()
    status=ndb.IntegerProperty()
    likes=ndb.IntegerProperty()
    soldto=ndb.StringProperty()
    date=ndb.DateTimeProperty(auto_now_add=True)

class Wishlist(ndb.Model):
    userId = ndb.IntegerProperty() 
    imageId=ndb.IntegerProperty()

class Level(ndb.Model):
  userName=ndb.StringProperty()
  level=ndb.IntegerProperty() 
  
class DatastoreFile(ndb.Model):
    data = ndb.BlobProperty(default=None)  # max size  < 1mb
    mimetype = ndb.StringProperty(required=True) 
    userId = ndb.IntegerProperty()  

class Review(ndb.Model):
  imageId=ndb.IntegerProperty()
  review=ndb.StringProperty()
  userId = ndb.IntegerProperty() 
  userName=ndb.StringProperty()
  date=ndb.DateTimeProperty(auto_now_add=True)


class BaseHandler(webapp2.RequestHandler):
  @webapp2.cached_property
  def auth(self):
    """Shortcut to access the auth instance as a property."""
    return auth.get_auth()

  @webapp2.cached_property
  def user_info(self):
    """Shortcut to access a subset of the user attributes that are stored
    in the session.

    The list of attributes to store in the session is specified in
      config['webapp2_extras.auth']['user_attributes'].
    :returns
      A dictionary with most user information
    """
    return self.auth.get_user_by_session()

  @webapp2.cached_property
  def user(self):
    """Shortcut to access the current logged in user.

    Unlike user_info, it fetches information from the persistence layer and
    returns an instance of the underlying model.

    :returns
      The instance of the user model associated to the logged in user.
    """
    u = self.user_info
    return self.user_model.get_by_id(u['user_id']) if u else None

  @webapp2.cached_property
  def user_model(self):
    """Returns the implementation of the user model.

    It is consistent with config['webapp2_extras.auth']['user_model'], if set.
    """    
    return self.auth.store.user_model

  @webapp2.cached_property
  def session(self):
      """Shortcut to access the current session."""
      return self.session_store.get_session(backend="datastore")

  def render_template(self, view_filename, params=None):
    if not params:
      params = {}
    user = self.user_info
    params['user'] = user
    path = os.path.join(os.path.dirname(__file__), 'views', view_filename)
    self.response.out.write(template.render(path, params))

  def display_message(self, message):
    """Utility function to display a template with a simple message."""
    params = {
      'message': message
    }
    self.render_template('message.html', params)

  # this is needed for webapp2 sessions to work
  def dispatch(self):
      # Get a session store for this request.
      self.session_store = sessions.get_store(request=self.request)

      try:
          # Dispatch the request.
          webapp2.RequestHandler.dispatch(self)
      finally:
          # Save all sessions.
          self.session_store.save_sessions(self.response)


    

class MainHandler(BaseHandler):
  def get(self):
    p=ndb.gql("SELECT * from Form ORDER BY likes DESC")
    products=p.get()
    products=p.fetch()
    q=ndb.gql("SELECT * from Form ORDER BY date DESC")
    items=q.get()
    items=q.fetch() 
    params = {'products':products,'items':items}    
    self.render_template('index.html', params)

class Index2Handler(BaseHandler):
  @user_required
  def get(self):
    p=ndb.gql("SELECT * from Form ORDER BY likes DESC")
    products=p.get()
    products=p.fetch()
    q=ndb.gql("SELECT * from Form ORDER BY date DESC")
    items=q.get()
    items=q.fetch()

    params = {'products':products,'items':items}    
    self.render_template('index2.html', params)

class PersonalHandler(BaseHandler):
  @user_required
  def get(self):
    user2 = self.user
    userName=user2.name
    q=Level.query(Level.userName==userName)
    level=q.get()
    level=q.fetch()[0]
    params = {'user2':user2,'level':level}
    self.render_template('personal_page.html', params)

  @user_required
  def post(self):
    product_name = self.request.get('product_name')
    time = self.request.get('time')
    # owner = self.request.get('owner')
    price = self.request.get('price')
    phone = self.request.get('phone')
    description = self.request.get('description')
    file = self.request.POST['file']
    x=self.user    
    m=x.key.id()
    entity = DatastoreFile(userId=m, data=file.value, mimetype=file.type)
    entity.put()
    form = Form(userId=m,product_name=product_name, likes=0,time=time, owner=self.user.name,price=price,phone=phone,description=description,imageId=entity.key.id())
    form.put()
    file_url = "http://%s/file/download/%d" % (self.request.host, entity.key.id())
    product_url = "http://%s/product_page/%d" % (self.request.host, entity.key.id())
    self.redirect('/personal_page')

class DownloadHandler(BaseHandler):
  def get(self, id):
        # can use get_by_id if you know the number id of the entity
    entity = DatastoreFile.get_by_id(int(id))
    self.response.headers['Content-Type'] = str(entity.mimetype)
    self.response.out.write(entity.data)        

class ProductlistHandler(BaseHandler):
  def get(self):
    p=ndb.gql("SELECT * from Form ORDER BY date DESC")
    forms=p.get()
    forms=p.fetch()
    forms2=[]
    for form in forms:
      if form.status!=1:
        forms2.append(form)       
    params = {'forms':forms2}
    self.render_template('product_list.html', params)
    
class Productlist2Handler(BaseHandler):
  def get(self):
    p=ndb.gql("SELECT * from Form ORDER BY date DESC")
    forms=p.get()
    forms=p.fetch()
    forms2=[]
    for form in forms:
      if form.status!=1:
        forms2.append(form)       
    params = {'forms':forms2}
    self.render_template('product_list2.html', params)
    

class SignupHandler(BaseHandler):
  def get(self):
    self.render_template('signup.html')

  def post(self):
    user_name = self.request.get('username')
    age = self.request.get('age')
    name = self.request.get('username')
    email = self.request.get('email')
    password = self.request.get('password')
    level=Level(userName=name,level=0)
    level.put()
    unique_properties = ['email_address']
    user_data = self.user_model.create_user(user_name,
      unique_properties,
      email_address=email, password_raw=password, name=name, age=age,
      verified=False)
    if not user_data[0]: #user_data is a tuple
      self.display_message('Unable to create user, the email or the username has been used!')
      return
    
    user = user_data[1]
    logging.info(user)
    user_id = user.get_id()

    token = self.user_model.create_signup_token(user_id)

    verification_url = self.uri_for('verification', type='v', user_id=user_id,
      signup_token=token, _full=True)

    msg = 'Send an email to user in order to verify their address. \
          They will be able to do so by visiting <a href="{url}">{url}</a>'

    self.display_message(msg.format(url=verification_url))

class ForgotPasswordHandler(BaseHandler):
  def get(self):
    self._serve_page()

  def post(self):
    username = self.request.get('username')

    user = self.user_model.get_by_auth_id(username)
    if not user:
      logging.info('Could not find any user entry for username %s', username)
      self._serve_page(not_found=True)
      return

    user_id = user.get_id()
    token = self.user_model.create_signup_token(user_id)

    verification_url = self.uri_for('verification', type='p', user_id=user_id,
      signup_token=token, _full=True)

    msg = 'Send an email to user in order to reset their password. \
          They will be able to do so by visiting <a href="{url}">{url}</a>'

    self.display_message(msg.format(url=verification_url))
  
  def _serve_page(self, not_found=False):
    username = self.request.get('username')
    params = {
      'username': username,
      'not_found': not_found
    }
    self.render_template('forgot.html', params)

class ProductLikeHandler(BaseHandler):
  def get(self,id):
    p=ndb.gql("SELECT * from Form where imageId=%d"%(int(id)))
    products=p.get()
    products=p.fetch()    
    q=ndb.gql("SELECT * from Review where imageId=%d"%(int(id)))
    reviews=q.get()
    reviews=q.fetch()
    params = {'products':products[0],'reviews':reviews}
    self.render_template('product_page.html', params)

  def post(self,id):
    a= self.request.get('likes')
    logging.info("%%%%%%%%%%%%%%%%"+a)
    p=ndb.gql("SELECT * from Form where imageId=%d" %(int(id)))
    logging.info(p)
    logging.info("ok*********")
    likes=p.get()
    likes=p.fetch()[0]
    likes.likes=likes.likes+1
    likes.put()
    logging.info("********************")

class ProductWishListHandler(BaseHandler):
  def post(self):
    a= self.request.get('imageIdW')
    a=int(a)
    x=self.user 
    userId=x.key.id()
    wishlist=Wishlist(userId=userId,imageId=a)
    wishlist.put() 

  def get(self):
    x=self.user    
    m=x.key.id()
    p=ndb.gql("SELECT * from Wishlist where userId=%d " %(m))
    wishlist=p.get()
    wishlist=p.fetch()
    q=ndb.gql("SELECT * from Form where status!=1")
    products2=q.get()
    products2=q.fetch()
    logging.info(wishlist)
    products=[]
    for i in products2:
      for j in wishlist:
        if i.imageId==j.imageId:
          logging.info(type(i.imageId))
          logging.info(type(j.imageId))
          products.append(i)
    logging.info(products)
    params = {'sellings':products}
    self.render_template('wishlist.html',params)

class ProductNotificationHandler(BaseHandler):
  def get(self):
    x=self.user    
    m=x.key.id()
    p=ndb.gql("SELECT * from Form where userId=%d and status!=1" %(m))
    products2=p.get()
    products2=p.fetch()
    q=ndb.gql("SELECT * from Wishlist")
    wishlist=q.get()
    wishlist=q.fetch()
    qqq=ndb.gql("SELECT * from User")
    user=qqq.get()
    user=qqq.fetch()
    products=[]
    for i in products2:
      for j in wishlist:
        if i.imageId==j.imageId:
          i.userId=j.userId
          for k in user:
            if k.key.id()==i.userId:
              mywishlistDic={}
              mywishlistDic['email']=k.email_address
              mywishlistDic['buyername']=k.name
              mywishlistDic['imageId']=i.imageId
              mywishlistDic['price']=i.price
              mywishlistDic['product_name']=i.product_name
              products.append(mywishlistDic)
    logging.info(products)
    n=x.name
    pp=ndb.gql("SELECT * from Form where status=1")
    pproducts2=pp.get()
    pproducts2=pp.fetch()
    buy=[]
    logging.info(pproducts2)
    for i in  pproducts2:
      if i.soldto==n:
        buy.append(i)
    logging.info(buy)
    params = {'sellings':products,'soldtos':buy}
    self.render_template('notification.html',params)


class ProductLike2Handler(BaseHandler):
  def get(self,id):
    p=ndb.gql("SELECT * from Form where imageId=%d"%(int(id)))
    products=p.get()
    products=p.fetch()    
    q=ndb.gql("SELECT * from Review where imageId=%d"%(int(id)))
    reviews=q.get()
    reviews=q.fetch()
    params = {'products':products[0],'reviews':reviews}
    self.render_template('product_page2.html', params)

  def post(self,id):
    # a= self.request.get('likes')
    a = 1
    logging.info("%%%%%%%%%%%%%%%%"+a)
    p=ndb.gql("SELECT * from Form where imageId=%d" %(int(id)))
    logging.info(p)
    logging.info("ok*********")
    likes=p.get()
    likes=p.fetch()[0]
    likes.likes=likes.likes+int(a)
    likes.put()
    logging.info("********************")
    
class ProductReviewHandler(BaseHandler):
  @user_required2
  def get(self,id):
    p=ndb.gql("SELECT * from Form where imageId=%d"%(int(id)))
    products=p.get()
    products=p.fetch()    
    q=ndb.gql("SELECT * from Review where imageId=%d"%(int(id)))
    reviews=q.get()
    reviews=q.fetch()
    params = {'products':products[0],'reviews':reviews}
    self.render_template('product_page.html', params)

class ProductReviewPostHandler(BaseHandler): 
  
  @user_required2
  def post(self):
    review=self.request.get('review')
    imageId2=self.request.get('imageId')
    logging.info(imageId2)
    imageId2=int(imageId2)
    x=self.user 
    userId=x.key.id()
    userName=x.name
    review=Review(review=review,imageId=imageId2,userId=userId,userName=userName)
    review.put()
    # self.redirect('/product_page/review/' + imageId2)
  
class SellingHandler(BaseHandler):
  @user_required
  def get(self):
    x=self.user    
    m=x.key.id()
    #sellings=Form.query(Form.userId=m)
    p=ndb.gql("SELECT * from Form where userId=%d and status!=1" %(m))
    sellings=p.get()
    sellings=p.fetch()
    params = {'sellings':sellings}
    self.render_template('selling.html', params)
  @user_required
  def post(self):
    a=self.request.get("sold")
    b=self.request.get("soldto")
    p=ndb.gql("SELECT * from Form where imageId=%d" %(int(a)))
    sellings=p.get()
    sellings=p.fetch()[0]
    sellings.status=1
    sellings.soldto=b
    logging.info("********************")
    logging.info(b)
    sellings.put()
    x=self.user 
    userId=x.key.id()
    userName=x.name
    q=Level.query(Level.userName==userName)
    level=q.get()
    level=q.fetch()[0]
    level.level=level.level+1
    level.put()
    self.redirect("/sold")
    
class SoldHandler(BaseHandler):
  @user_required
  def get(self):
    x=self.user    
    m=x.key.id()
    #sellings=Form.query(Form.userId=m)
    p=ndb.gql("SELECT * from Form where userId=%d and status=1" %(m))
    logging.info("ok")
    solds=p.get()
    solds=p.fetch()
    params = {'solds':solds}
    self.render_template('sold.html', params)
    
class VerificationHandler(BaseHandler):
  def get(self, *args, **kwargs):
    user = None
    user_id = kwargs['user_id']
    signup_token = kwargs['signup_token']
    verification_type = kwargs['type']

    # it should be something more concise like
    # self.auth.get_user_by_token(user_id, signup_token)
    # unfortunately the auth interface does not (yet) allow to manipulate
    # signup tokens concisely
    user, ts = self.user_model.get_by_auth_token(int(user_id), signup_token,
      'signup')

    if not user:
      logging.info('Could not find any user with id "%s" signup token "%s"',
        user_id, signup_token)
      self.abort(404)
    
    # store user data in the session
    self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)

    if verification_type == 'v':
      # remove signup token, we don't want users to come back with an old link
      self.user_model.delete_signup_token(user.get_id(), signup_token)

      if not user.verified:
        user.verified = True
        user.put()

      self.display_message('User email address has been verified. <a href="/index2">Mainpage</a>' )
      
      return
    elif verification_type == 'p':
      # supply user to the page
      params = {
        'user': user,
        'token': signup_token
      }
      self.render_template('resetpassword.html', params)
    else:
      logging.info('verification type not supported')
      self.abort(404)

class SetPasswordHandler(BaseHandler):

  @user_required
  def post(self):
    password = self.request.get('password')
    old_token = self.request.get('t')

    if not password or password != self.request.get('confirm_password'):
      self.display_message('passwords do not match')
      return

    user = self.user
    user.set_password(password)
    user.put()

    # remove signup token, we don't want users to come back with an old link
    self.user_model.delete_signup_token(user.get_id(), old_token)
    
    self.display_message('Password updated')

class LoginHandler(BaseHandler):
  def get(self):
    self._serve_page()

  def post(self):
    username = self.request.get('username')
    password = self.request.get('password')
    try:
      u = self.auth.get_user_by_password(username, password, remember=True,
        save_session=True)
      # params = {
      # 'username': u,
      # }
      # self.render_template('index2.html', params)
      self.redirect(self.uri_for('index2'))
    except (InvalidAuthIdError, InvalidPasswordError) as e:
      logging.info('Login failed for user %s because of %s', username, type(e))
      self._serve_page(True)

  def _serve_page(self, failed=False):
    username = self.request.get('username')
    params = {
      'username': username,
      'failed': failed
    }
    self.render_template('login.html', params)

class LogoutHandler(BaseHandler):
  def get(self):
    self.auth.unset_session()
    self.redirect(self.uri_for('home'))

class AuthenticatedHandler(BaseHandler):
  @user_required
  def get(self):
    self.render_template('index.html')

config = {
  'webapp2_extras.auth': {
    'user_model': 'models.User',
    'user_attributes': ['name']
  },
  'webapp2_extras.sessions': {
    'secret_key': 'YOUR_SECRET_KEY'
  }
}

app = webapp2.WSGIApplication([
    webapp2.Route('/', MainHandler, name='home'),
    webapp2.Route('/signup', SignupHandler),
    webapp2.Route('/<type:v|p>/<user_id:\d+>-<signup_token:.+>',
      handler=VerificationHandler, name='verification'),
    webapp2.Route('/index2', Index2Handler, name='index2'),
    webapp2.Route('/password', SetPasswordHandler),
    webapp2.Route('/login', LoginHandler, name='login'),
    webapp2.Route('/logout', LogoutHandler, name='logout'),
    webapp2.Route('/personal_page', PersonalHandler, name='personal_page'),
    webapp2.Route('/forgot', ForgotPasswordHandler, name='forgot'),
    webapp2.Route('/authenticated', AuthenticatedHandler, name='authenticated'),
    ('/file/download/(\d+)', DownloadHandler),
    ('/product_list',ProductlistHandler),
    ('/product_list2',Productlist2Handler),
    ('/product_page/like/(\d+)',ProductLikeHandler),
    ('/wishlist',ProductWishListHandler),
    ('/notification',ProductNotificationHandler),
    ('/product_page2/like/(\d+)',ProductLike2Handler),
    ('/product_page/review/(\d+)',ProductReviewHandler),
    webapp2.Route('/product_page/review',ProductReviewPostHandler),
    ('/selling',SellingHandler),
    ('/sold',SoldHandler),
], debug=True, config=config)

logging.getLogger().setLevel(logging.DEBUG)
