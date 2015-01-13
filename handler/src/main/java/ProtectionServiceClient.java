import org.apache.thrift.TException;
import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.protocol.TProtocol;
import org.apache.thrift.transport.TSocket;
import org.apache.thrift.transport.TTransport;
import security.Compartment;
import security.Group;
import security.Level;
import security.ProtectedDocument;
import security.ProtectedField;
import security.ProtectedKey;
import security.ProtectionService;
import security.SecurityContainer;
import security.User;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class ProtectionServiceClient {
    public static void main(String [] args) {


        try {
            TTransport transport;

            transport = new TSocket("localhost", 9090);
            transport.open();

            TProtocol protocol = new  TBinaryProtocol(transport);
            ProtectionService.Client client = new ProtectionService.Client(protocol);

            perform(client);

            transport.close();
        } catch (TException x) {
            x.printStackTrace();
        }
    }

    private static void perform(ProtectionService.Client client) throws TException
    {
        SecurityContainer container = new SecurityContainer();
        container.setCompartments(EnumSet.of(Compartment.ALPHA));
        container.setLevels(EnumSet.of(Level.PUBLIC));
        container.setGroups(EnumSet.of(Group.HR));

        SecurityContainer other_container = new SecurityContainer();
        other_container.setCompartments(EnumSet.of(Compartment.BRAVO));
        other_container.setLevels(EnumSet.of(Level.SENSITIVE));
        other_container.setGroups(EnumSet.of(Group.HR));

        SecurityContainer userContainer = new SecurityContainer();
        userContainer.setCompartments(EnumSet.of(Compartment.ALPHA,Compartment.BRAVO));
        userContainer.setLevels(EnumSet.of(Level.PUBLIC,Level.SENSITIVE));
        userContainer.setGroups(EnumSet.of(Group.HR));


        User user = new User();
        user.setUsername("test");
        user.setPermissions(userContainer);

        ProtectedDocument document = new ProtectedDocument();
        Map<ProtectedKey, ProtectedField> fields = new HashMap<>();

        ProtectedKey alphaKey = new ProtectedKey();
        alphaKey.setName("Test");
        ProtectedField alphaField = new ProtectedField();
        alphaField.setMarkings(container);
        alphaField.setValue("some value");

        ProtectedKey bravoKey = new ProtectedKey();
        bravoKey.setName("Salary");
        ProtectedField bravoField = new ProtectedField();
        bravoField.setMarkings(other_container);
        bravoField.setValue("100,000");

        fields.put(bravoKey,bravoField);

        fields.put(alphaKey,alphaField);
        document.setFields(fields);

        document.setOverallMarkings(other_container);
        List<ProtectedDocument> documents = new LinkedList<>();
        documents.add(document);
        List<ProtectedDocument> products = client.authorize(user,documents);
        for(ProtectedDocument product : products){
            for(ProtectedKey key : product.getFields().keySet()){
                System.out.println("key: " + key);
                System.out.println("field: " + product.getFields().get(key));
            }
        }

    }
}