import junit.framework.Assert;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import security.Compartment;
import security.Group;
import security.Level;
import security.ProtectedDocument;
import security.ProtectedField;
import security.ProtectedKey;
import security.SecurityContainer;
import security.User;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

public class ProtectionServiceHandlerTest {

    private SecurityContainer dataContainer;
    private SecurityContainer userContainer;
    private User user;
    private ProtectedDocument document;
    private Map<ProtectedKey, ProtectedField> fields;
    private ProtectedKey alphaKey;
    private ProtectedField alphaField;

    private ProtectionServiceHandler handler;

    @Before
    public void setUp() throws Exception {
        document = new ProtectedDocument();
        fields = new HashMap<>();
        alphaKey = new ProtectedKey();
        alphaKey.setName("Test");

        alphaField = new ProtectedField();
        alphaField.setValue("some value");

        dataContainer= new SecurityContainer();
        userContainer =  new SecurityContainer();
        user = new User();
        user.setUsername("test");

        handler = new ProtectionServiceHandler();
    }

    @After
    public void tearDown() throws Exception {

    }

    @Test
    public void processUserWithPublic_DataHasNoLevels_FieldHasNoLevels() throws Exception{
        userContainer.setCompartments(EnumSet.of(Compartment.ALPHA, Compartment.BRAVO));
        userContainer.setLevels(EnumSet.of(Level.PUBLIC));
        userContainer.setGroups(EnumSet.of(Group.HR));
        user.setPermissions(userContainer);
        dataContainer.setCompartments(EnumSet.allOf(Compartment.class));
        dataContainer.setLevels(EnumSet.noneOf(Level.class));
        dataContainer.setGroups(EnumSet.allOf(Group.class));
        SecurityContainer fieldContainer = new SecurityContainer();
        fieldContainer.setCompartments(EnumSet.allOf(Compartment.class));
        fieldContainer.setLevels(EnumSet.noneOf(Level.class));
        fieldContainer.setGroups(EnumSet.allOf(Group.class));
        alphaField.setMarkings(fieldContainer);
        fields.put(alphaKey, alphaField);
        document.setFields(fields);
        document.setOverallMarkings(dataContainer);
        List<ProtectedDocument> documents = new LinkedList<>();
        documents.add(document);
        assertEquals(1, handler.authorize(user,documents).size());
        assertEquals("some value",documents.get(0).getFields().get(alphaKey).getValue());
    }

    @Test
    public void processUserWithPublic_DataHasNoLevels_FieldHasPublic() throws Exception{
        userContainer.setCompartments(EnumSet.of(Compartment.ALPHA, Compartment.BRAVO));
        userContainer.setLevels(EnumSet.of(Level.PUBLIC));
        userContainer.setGroups(EnumSet.of(Group.HR));
        user.setPermissions(userContainer);
        dataContainer.setCompartments(EnumSet.allOf(Compartment.class));
        dataContainer.setLevels(EnumSet.noneOf(Level.class));
        dataContainer.setGroups(EnumSet.allOf(Group.class));
        SecurityContainer fieldContainer = new SecurityContainer();
        fieldContainer.setCompartments(EnumSet.allOf(Compartment.class));
        fieldContainer.setLevels(EnumSet.of(Level.PUBLIC));
        fieldContainer.setGroups(EnumSet.allOf(Group.class));
        alphaField.setMarkings(fieldContainer);
        fields.put(alphaKey, alphaField);
        document.setFields(fields);
        document.setOverallMarkings(dataContainer);
        List<ProtectedDocument> documents = new LinkedList<>();
        documents.add(document);
        assertEquals(1, handler.authorize(user,documents).size());
        assertEquals("some value",documents.get(0).getFields().get(alphaKey).getValue());
    }

    @Test
    public void processUserWithPublic_DataHasNoLevels_FieldHasSensitive() throws Exception{
        userContainer.setCompartments(EnumSet.of(Compartment.ALPHA, Compartment.BRAVO));
        userContainer.setLevels(EnumSet.of(Level.PUBLIC));
        userContainer.setGroups(EnumSet.of(Group.HR));
        user.setPermissions(userContainer);
        dataContainer.setCompartments(EnumSet.allOf(Compartment.class));
        dataContainer.setLevels(EnumSet.noneOf(Level.class));
        dataContainer.setGroups(EnumSet.allOf(Group.class));
        SecurityContainer fieldContainer = new SecurityContainer();
        fieldContainer.setCompartments(EnumSet.allOf(Compartment.class));
        fieldContainer.setLevels(EnumSet.of(Level.SENSITIVE));
        fieldContainer.setGroups(EnumSet.allOf(Group.class));
        alphaField.setMarkings(fieldContainer);
        fields.put(alphaKey, alphaField);
        document.setFields(fields);
        document.setOverallMarkings(dataContainer);
        List<ProtectedDocument> documents = new LinkedList<>();
        documents.add(document);
        assertEquals(1, handler.authorize(user,documents).size());
        assertNull(documents.get(0).getFields().get(alphaKey).getValue());
    }

    @Test
    public void processUserWithSensitiveAndPublic_DataHasNoLevels() throws Exception{
        userContainer.setCompartments(EnumSet.of(Compartment.ALPHA, Compartment.BRAVO));
        userContainer.setLevels(EnumSet.of(Level.SENSITIVE,Level.PUBLIC));
        userContainer.setGroups(EnumSet.of(Group.HR));
        user.setPermissions(userContainer);
        dataContainer.setCompartments(EnumSet.allOf(Compartment.class));
        dataContainer.setLevels(EnumSet.noneOf(Level.class));
        dataContainer.setGroups(EnumSet.allOf(Group.class));
        alphaField.setMarkings(dataContainer);
        fields.put(alphaKey,alphaField);
        document.setFields(fields);
        document.setOverallMarkings(dataContainer);
        List<ProtectedDocument> documents = new LinkedList<>();
        documents.add(document);
        assertEquals(1, handler.authorize(user,documents).size());
    }

    @Test
    public void processUserWithSensitiveAndPublic_DataHasPublic() throws Exception{
        userContainer.setCompartments(EnumSet.of(Compartment.ALPHA, Compartment.BRAVO));
        userContainer.setLevels(EnumSet.of(Level.SENSITIVE,Level.PUBLIC));
        userContainer.setGroups(EnumSet.of(Group.HR));
        user.setPermissions(userContainer);
        dataContainer.setCompartments(EnumSet.allOf(Compartment.class));
        dataContainer.setLevels(EnumSet.of(Level.PUBLIC));
        dataContainer.setGroups(EnumSet.allOf(Group.class));
        alphaField.setMarkings(dataContainer);
        fields.put(alphaKey,alphaField);
        document.setFields(fields);
        document.setOverallMarkings(dataContainer);
        List<ProtectedDocument> documents = new LinkedList<>();
        documents.add(document);
        assertEquals(1, handler.authorize(user,documents).size());
    }

    @Test
    public void processUserWithSensitiveAndPublic_DataHasSensitive() throws Exception{
        userContainer.setCompartments(EnumSet.of(Compartment.ALPHA, Compartment.BRAVO));
        userContainer.setLevels(EnumSet.of(Level.SENSITIVE, Level.PUBLIC));
        userContainer.setGroups(EnumSet.of(Group.HR));
        user.setPermissions(userContainer);
        dataContainer.setCompartments(EnumSet.allOf(Compartment.class));
        dataContainer.setLevels(EnumSet.of(Level.SENSITIVE));
        dataContainer.setGroups(EnumSet.allOf(Group.class));
        alphaField.setMarkings(dataContainer);
        fields.put(alphaKey,alphaField);
        document.setFields(fields);
        document.setOverallMarkings(dataContainer);
        List<ProtectedDocument> documents = new LinkedList<>();
        documents.add(document);
        assertEquals(1, handler.authorize(user,documents).size());
    }

    @Test
    public void processUserWithSensitive_DataHasNoLevels() throws Exception{
        userContainer.setCompartments(EnumSet.of(Compartment.ALPHA, Compartment.BRAVO));
        userContainer.setLevels(EnumSet.of(Level.SENSITIVE));
        userContainer.setGroups(EnumSet.of(Group.HR));
        user.setPermissions(userContainer);
        dataContainer.setCompartments(EnumSet.allOf(Compartment.class));
        dataContainer.setLevels(EnumSet.noneOf(Level.class));
        dataContainer.setGroups(EnumSet.allOf(Group.class));
        alphaField.setMarkings(dataContainer);
        fields.put(alphaKey,alphaField);
        document.setFields(fields);
        document.setOverallMarkings(dataContainer);
        List<ProtectedDocument> documents = new LinkedList<>();
        documents.add(document);
        assertEquals(1, handler.authorize(user,documents).size());
    }

    @Test
    public void processUserWithSensitive_DataHasPublic() throws Exception{
        userContainer.setCompartments(EnumSet.of(Compartment.ALPHA, Compartment.BRAVO));
        userContainer.setLevels(EnumSet.of(Level.SENSITIVE));
        userContainer.setGroups(EnumSet.of(Group.HR));
        user.setPermissions(userContainer);
        dataContainer.setCompartments(EnumSet.allOf(Compartment.class));
        dataContainer.setLevels(EnumSet.of(Level.PUBLIC));
        dataContainer.setGroups(EnumSet.allOf(Group.class));
        alphaField.setMarkings(dataContainer);
        fields.put(alphaKey,alphaField);
        document.setFields(fields);
        document.setOverallMarkings(dataContainer);
        List<ProtectedDocument> documents = new LinkedList<>();
        documents.add(document);
        assertEquals(0, handler.authorize(user,documents).size());
    }

    @Test
    public void processUserWithSensitive_DataHasSensitive() throws Exception{
        userContainer.setCompartments(EnumSet.of(Compartment.ALPHA, Compartment.BRAVO));
        userContainer.setLevels(EnumSet.of(Level.SENSITIVE));
        userContainer.setGroups(EnumSet.of(Group.HR));
        user.setPermissions(userContainer);
        dataContainer.setCompartments(EnumSet.allOf(Compartment.class));
        dataContainer.setLevels(EnumSet.of(Level.SENSITIVE));
        dataContainer.setGroups(EnumSet.allOf(Group.class));
        alphaField.setMarkings(dataContainer);
        fields.put(alphaKey,alphaField);
        document.setFields(fields);
        document.setOverallMarkings(dataContainer);
        List<ProtectedDocument> documents = new LinkedList<>();
        documents.add(document);
        assertEquals(1, handler.authorize(user,documents).size());
    }

    @Test
    public void processUserWithPublic_DataHasNoLevels() throws Exception{
        userContainer.setCompartments(EnumSet.of(Compartment.ALPHA, Compartment.BRAVO));
        userContainer.setLevels(EnumSet.of(Level.PUBLIC));
        userContainer.setGroups(EnumSet.of(Group.HR));
        user.setPermissions(userContainer);
        dataContainer.setCompartments(EnumSet.allOf(Compartment.class));
        dataContainer.setLevels(EnumSet.noneOf(Level.class));
        dataContainer.setGroups(EnumSet.allOf(Group.class));
        alphaField.setMarkings(dataContainer);
        fields.put(alphaKey,alphaField);
        document.setFields(fields);
        document.setOverallMarkings(dataContainer);
        List<ProtectedDocument> documents = new LinkedList<>();
        documents.add(document);
        assertEquals(1, handler.authorize(user,documents).size());
    }
    @Test
    public void processUserWithPublic_DataHasPublic() throws Exception{
        userContainer.setCompartments(EnumSet.of(Compartment.ALPHA, Compartment.BRAVO));
        userContainer.setLevels(EnumSet.of(Level.PUBLIC));
        userContainer.setGroups(EnumSet.of(Group.HR));
        user.setPermissions(userContainer);
        dataContainer.setCompartments(EnumSet.allOf(Compartment.class));
        dataContainer.setLevels(EnumSet.of(Level.PUBLIC));
        dataContainer.setGroups(EnumSet.allOf(Group.class));
        alphaField.setMarkings(dataContainer);
        fields.put(alphaKey,alphaField);
        document.setFields(fields);
        document.setOverallMarkings(dataContainer);
        List<ProtectedDocument> documents = new LinkedList<>();
        documents.add(document);
        assertEquals(1, handler.authorize(user,documents).size());
    }

    @Test
    public void processUserWithPublic_DataHasSensitive() throws Exception{
        userContainer.setCompartments(EnumSet.of(Compartment.ALPHA, Compartment.BRAVO));
        userContainer.setLevels(EnumSet.of(Level.PUBLIC));
        userContainer.setGroups(EnumSet.of(Group.HR));
        user.setPermissions(userContainer);
        dataContainer.setCompartments(EnumSet.allOf(Compartment.class));
        dataContainer.setLevels(EnumSet.of(Level.SENSITIVE));
        dataContainer.setGroups(EnumSet.allOf(Group.class));
        alphaField.setMarkings(dataContainer);
        fields.put(alphaKey,alphaField);
        document.setFields(fields);
        document.setOverallMarkings(dataContainer);
        List<ProtectedDocument> documents = new LinkedList<>();
        documents.add(document);
        assertEquals(0, handler.authorize(user,documents).size());
    }

    @Test
    public void processUserWithNoLevels_DataHasNoLevels() throws Exception{
        userContainer.setCompartments(EnumSet.of(Compartment.ALPHA, Compartment.BRAVO));
        userContainer.setLevels(EnumSet.noneOf(Level.class));
        userContainer.setGroups(EnumSet.of(Group.HR));
        user.setPermissions(userContainer);
        dataContainer.setCompartments(EnumSet.allOf(Compartment.class));
        dataContainer.setLevels(EnumSet.noneOf(Level.class));
        dataContainer.setGroups(EnumSet.allOf(Group.class));
        alphaField.setMarkings(dataContainer);
        fields.put(alphaKey,alphaField);
        document.setFields(fields);
        document.setOverallMarkings(dataContainer);
        List<ProtectedDocument> documents = new LinkedList<>();
        documents.add(document);
        assertEquals(1, handler.authorize(user,documents).size());
    }
    @Test
    public void processUserWithNoLevels_DataHasPublic() throws Exception{
        userContainer.setCompartments(EnumSet.of(Compartment.ALPHA, Compartment.BRAVO));
        userContainer.setLevels(EnumSet.noneOf(Level.class));
        userContainer.setGroups(EnumSet.of(Group.HR));
        user.setPermissions(userContainer);
        dataContainer.setCompartments(EnumSet.allOf(Compartment.class));
        dataContainer.setLevels(EnumSet.of(Level.PUBLIC));
        dataContainer.setGroups(EnumSet.allOf(Group.class));
        alphaField.setMarkings(dataContainer);
        fields.put(alphaKey,alphaField);
        document.setFields(fields);
        document.setOverallMarkings(dataContainer);
        List<ProtectedDocument> documents = new LinkedList<>();
        documents.add(document);
        assertEquals(0, handler.authorize(user,documents).size());
    }

    @Test
    public void processUserWithNoLevels_DataHasSensitive() throws Exception{
        userContainer.setCompartments(EnumSet.of(Compartment.ALPHA, Compartment.BRAVO));
        userContainer.setLevels(EnumSet.noneOf(Level.class));
        userContainer.setGroups(EnumSet.of(Group.HR));
        user.setPermissions(userContainer);
        dataContainer.setCompartments(EnumSet.allOf(Compartment.class));
        dataContainer.setLevels(EnumSet.of(Level.SENSITIVE));
        dataContainer.setGroups(EnumSet.allOf(Group.class));
        alphaField.setMarkings(dataContainer);
        fields.put(alphaKey,alphaField);
        document.setFields(fields);
        document.setOverallMarkings(dataContainer);
        List<ProtectedDocument> documents = new LinkedList<>();
        documents.add(document);
        assertEquals(0, handler.authorize(user,documents).size());
    }
}