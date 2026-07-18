# Protocol Notes
  1. When requesting Data from the server, the delivered data will always be in the format of a serialized vector of Messages.
  2. When Sending Key bundle data to the server, bundles will be sent individually.
  3. When requesting data from the Database, the response's `InboundDataProtocol.routing_data()` will return the Address of the user who requested the data.
  4. When serving key bundle requests, the IO implementor should automatically extract and delete the served key bundle to prevent reuse.