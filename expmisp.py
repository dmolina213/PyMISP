from pymisp import ExpandedPyMISP
#from keys import url, key, verifycert
misp = ExpandedPyMISP('https://misp.kamuning176.com','RCA3rzX3q8tozY3NTw2yzwU96NnFnWscEnOsR8HD',True )
result = misp.search_index(published=True,  eventinfo='NRD', pythonify=True)
