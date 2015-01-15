// http://www.oracle.com/webfolder/technetwork/tutorials/obe/db/10g/r2/prod/security/ols/ols_otn.htm
//Types associated with Oracle OLS

namespace java security
namespace py security


enum Level{
    PUBLIC,
    SENSITIVE
}

//OR logic
enum Group{
     IT,
     HR
}

//AND logic
enum Compartment{
   ALPHA,
   BRAVO
}

/**
    Represents the known security parameters that can be associated with a document.
    Use of the empty set is encouraged over the use of NULL values.
 */
struct SecurityContainer{
     1: set<Level> levels,
     2: set<Group> groups,
     3: set<Compartment> compartments,
}

/**
    The "user" requesting access to a specific set of data.
 */
struct User{
    1: SecurityContainer permissions;
    2: optional string username;
}

/**
    A field that you want to protect.  The use of string values is used here as exploring
    further types such as date and numeric values are largely irrelevant to the underlying value
    and its associated security markings.
 */
struct ProtectedField{
      1: string value;
      2: SecurityContainer markings;
}

/**
     A unique key implementation that ensures we have abstracted away the "string"
     API.
 */
struct ProtectedKey{
       1: string name;
}

/**
   Represents a document, this is effectively a row in relational database terms.  Each field or cell can be
   marked with a set of security markings.
 */
struct ProtectedDocument{
      1: map<ProtectedKey,ProtectedField> fields;
      2: SecurityContainer overallMarkings; //document level
}

/**
*  The use of this service ensures that data is returned and processed in accordance with its security markings.
*  In the event a user does NOT have access to a specific protected field, the fields value is set to NULL.  It is
*  up to the receiving client to appropriately remove data based on any associated business logic.
**/
service ProtectionService{
      //Nulls fields you can't see
      list<ProtectedDocument> authorize(1: User user, 2: list<ProtectedDocument> fields),
}
