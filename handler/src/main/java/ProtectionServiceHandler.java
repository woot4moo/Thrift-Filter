import com.google.common.annotations.VisibleForTesting;
import org.apache.thrift.TException;
import security.Compartment;
import security.Group;
import security.Level;
import security.ProtectedDocument;
import security.ProtectedField;
import security.ProtectedKey;
import security.ProtectionService;
import security.User;

import java.util.EnumSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

public class ProtectionServiceHandler implements ProtectionService.Iface{

    public List<ProtectedDocument> authorize(User user, List<ProtectedDocument> fields) throws TException {
        return new LinkedList<>(process(user,fields));
    }

    @VisibleForTesting
    protected List<ProtectedDocument> process(User user, List<ProtectedDocument> documents){
        EnumSet<Level> levels = EnumSet.copyOf(user.getPermissions().getLevels());
        EnumSet<Group> groups = EnumSet.copyOf(user.getPermissions().getGroups());
        EnumSet<Compartment> compartments = EnumSet.copyOf(user.getPermissions().getCompartments());

        Iterator<ProtectedDocument> documentIterator = documents.iterator();
        while(documentIterator.hasNext()){
            ProtectedDocument document = documentIterator.next();
            EnumSet<Level> documentLevels = EnumSet.copyOf(document.getOverallMarkings().getLevels());
            documentLevels.removeAll(levels);
            if(!documentLevels.isEmpty()){
                System.out.println("Document levels:" + documentLevels);
                documentIterator.remove();
                System.out.println("Document has been nulled");
                continue;
            }
            EnumSet<Group> documentGroups = EnumSet.copyOf(document.getOverallMarkings().getGroups());
            documentGroups.retainAll(groups);
            if(documentGroups.isEmpty() && !document.getOverallMarkings().getGroups().isEmpty()){
                documentIterator.remove();
                continue;
            }
            /*
            EnumSet<Compartment> documentCompartments = EnumSet.copyOf(document.getOverallMarkings().getCompartments());
            if(!documentCompartments.complementOf(compartments).isEmpty()){
                documentIterator.remove();
                System.out.println("Document has been nulled");
                System.out.println(documentCompartments.complementOf(compartments));
                continue;
            }*/
            for(ProtectedKey key : document.getFields().keySet()){
                ProtectedField field = document.getFields().get(key);
                EnumSet<Level> fieldLevels = EnumSet.copyOf(field.getMarkings().getLevels());
                fieldLevels.removeAll(levels);
                if(!fieldLevels.isEmpty()){
                    document.getFields().get(key).setValue(null);
                    System.out.println("Field has been nulled");
                }

                EnumSet<Group> fieldGroups = EnumSet.copyOf(field.getMarkings().getGroups());
                fieldGroups.retainAll(groups);
                if(fieldGroups.isEmpty() && !field.getMarkings().getGroups().isEmpty()){
                   field.setValue(null);
                }
            }
        }
        return documents;
    }
}
