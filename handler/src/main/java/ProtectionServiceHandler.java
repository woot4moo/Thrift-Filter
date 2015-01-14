import com.google.common.annotations.VisibleForTesting;
import org.apache.thrift.TException;
import security.Compartment;
import security.Group;
import security.Level;
import security.ProtectedDocument;
import security.ProtectedField;
import security.ProtectedKey;
import security.ProtectionService;
import security.SecurityContainer;
import security.User;

import java.util.ArrayDeque;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

public class ProtectionServiceHandler implements ProtectionService.Iface{

    public List<ProtectedDocument> authorize(User user, List<ProtectedDocument> fields) throws TException {
        return new LinkedList<>(process(user,fields));
    }

    /**
     * Processes the supplied documents and appropriately nulls out values that the supplied user
     * should not have access to.
     *
     * @param user - The user that is requesting access
     * @param documents - The data that is to be accessed and filtered
     *
     * @return The remaining documents that can be seen
     *
     * @see security.User
     * @see security.ProtectedDocument
     */
    @VisibleForTesting
    protected List<ProtectedDocument> process(User user, List<ProtectedDocument> documents){
        if(null == documents || null == user || documents.isEmpty()){
            return new LinkedList<>();
        }
        Iterator<ProtectedDocument> documentIterator = documents.iterator();
        while(documentIterator.hasNext()){
            ProtectedDocument document = documentIterator.next();
            if(shouldRemove(document.getOverallMarkings(),user)){
                documentIterator.remove();
                continue;
            }
            for(ProtectedKey key : document.getFields().keySet()){
                ProtectedField field = document.getFields().get(key);
                if(shouldRemove(field.getMarkings(),user)){
                    document.getFields().get(key).setValue(null);
                    continue;
                }
            }
        }
        return documents;
    }

    /**
     * Determines if the record should be removed based on supplied parameters.
     * @param container - The data's permission set
     * @param user - The user's accesses
     * @return  True in the event that an audit has failed, False otherwise
     */
    private boolean shouldRemove(SecurityContainer container, User user){
        EnumSet<Level> levels = EnumSet.copyOf(container.getLevels());
        levels.removeAll(user.getPermissions().getLevels());

        EnumSet<Group> groups = EnumSet.copyOf(container.getGroups());
        groups.retainAll(user.getPermissions().getGroups());

        EnumSet<Compartment> compartments = EnumSet.copyOf(container.getCompartments());
        compartments.removeAll(user.getPermissions().getCompartments());

        return (   ( !levels.isEmpty())
                 ||( groups.isEmpty() && !container.getGroups().isEmpty())
                 ||( !compartments.isEmpty())
               );
    }
}
