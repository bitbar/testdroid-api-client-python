from testdroid import Testdroid
import sys
api_key = sys.argv[1]
testd = Testdroid(apikey=api_key)
def createproject():

    proj = testd.create_project("Helloworld102", "CALABASH")
    if proj.has_key('id'):
        print "Project Created"
    else:
        print "Error creating project"
        sys.exit(1)

    testd.delete_project(proj['id'])
    print "project deleted"

def validate_api():
    testd.get_me()
    print "user api validated"


validate_api()
createproject()
#deleteproject()
