from sqlalchemy import create_engine
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Boolean, ForeignKey

Base = declarative_base()

pathParameterType = 'path parameter'
authorizationHeaderParameterType = 'authorization header'
queryParameterType = 'query parameter'
bodyParameterType = 'body parameter'

responseFormatJSON = 'application/json'
responseFormatTextPlain = 'text/plain'

class User(Base):

    def __init__(self, name, email):
        self.name = name
        self.email = email
        
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))

    @property
    def serialize(self):
        """return object data in easily serializable format"""
        return {
            'name'        : self.name,
            'id'          : self.id,
        }

class RestCall(Base):

    def __init__(self, method, path, user_id):
        self.method = method
        self.path = path
        self.user_id = user_id

    __tablename__ = 'rest_call'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'))    # user who last edited this call
    method = Column(String(8))
    path = Column(String(64))
    description = Column(String(512))
    exampleRequest = Column(String(512))
    exampleResponse = Column(String(2048))

    parameters = relationship("Parameter",
        back_populates='restCall',
        cascade="all, delete, delete-orphan")

    def name(self):
        return self.method+' '+self.path

    def setDescription(self, description):
        self.description = description
        return self

    def setExampleRequest(self, exampleRequest):
        self.exampleRequest = exampleRequest
        return self

    def setExampleResponse(self, exampleResponse):
        self.exampleResponse = exampleResponse
        return self

    def __repr__(self):
        return "<RestCall(method='%s', path='%s')>" % (
            self.method, self.path)

    def requirePathParam(self, name, range, description, example):
        self.parameters.append(
            Parameter(self, pathParameterType, name, range, description, True, example))
        return self

    def requireAuthenticationBearerToken(self, description, example):
        self.parameters.append(
            Parameter(self, authorizationHeaderParameterType, 'Bearer', 'String', description, True, example))
        return self

    def requireAuthenticationBasicCredentials(self, description, example):
        self.parameters.append(
            Parameter(self, authorizationHeaderParameterType, 'Basic', 'String, Base64 encoded client credentials.', description, True, example))
        return self

    def requireQueryParam(self, name, range, description, example):
        self.parameters.append(
            Parameter(self, queryParameterType, name, range, description, True, example))
        return self

    def optionalQueryParam(self, name, range, description, default):
        self.parameters.append(
            Parameter(self, queryParameterType, name, range, description, False, default))
        return self

    def requireBodyParam(self, name, range, description, example):
        self.parameters.append(
            Parameter(self, bodyParameterType, name, range, description, True, example))
        return self

    def setResponseFormatJSON(self):
        self.responseFormat = responseFormatJSON
        return self

    def setResponseFormatTextPlain(self):
        self.responseFormat = responseFormatTextPlain
        return self

class Parameter(Base):

    def __init__(self, aRestCall, type, name, range, description, required, default):
        self.restCall = aRestCall
        self.type = type
        self.name = name
        self.range = range
        self.description = description
        self.required = required
        self.default = default

    __tablename__ = 'parameter'

    id = Column(Integer, primary_key=True)
    restCallId = Column(Integer, ForeignKey('rest_call.id'))
    restCall = relationship(RestCall, back_populates='parameters')
    type = Column(String(32))
    name = Column(String(32))
    range = Column(String(64))
    description = Column(String(256))
    required = Column(Boolean)
    default = Column(String(256))

    def __repr__(self):
        return "<Parameter(type='%s', name='%s', range='%s')>" % (
            self.type, self.name, self.range)

db_connection_info = 'postgresql+psycopg2:///api_ed_db'

if __name__ == '__main__':
    engine = create_engine(db_connection_info)
    Base.metadata.create_all(engine)
