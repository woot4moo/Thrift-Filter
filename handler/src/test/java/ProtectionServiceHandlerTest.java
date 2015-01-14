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
    private ProtectedKey betaKey;
    private ProtectedField betaField;

    private ProtectionServiceHandler handler;

    @Before
    public void setUp() throws Exception {
        document = new ProtectedDocument();
        fields = new HashMap<>();
        alphaKey = new ProtectedKey();
        alphaKey.setName("Alpha");

        alphaField = new ProtectedField();
        alphaField.setValue("some value");

        betaKey = new ProtectedKey();
        betaKey.setName("Beta");

        betaField = new ProtectedField();
        betaField.setValue("100000");

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
    public void processUserWithPublic_DataHasNoLevels_MultipleFieldsHaveDifferingLevels() throws Exception{
                userContainer.setCompartments(EnumSet.allOf(Compartment.class)); 
        userContainer.setLevels(EnumSet.of(Level.PUBLIC));
        userContainer.setGroups(EnumSet.of(Group.HR));
        user.setPermissions(userContainer);
        dataContainer.setCompartments(EnumSet.allOf(Compartment.class));
        dataContainer.setLevels(EnumSet.noneOf(Level.class));
        dataContainer.setGroups(EnumSet.allOf(Group.class));

        SecurityContainer alphaFieldContainer = new SecurityContainer();
        alphaFieldContainer.setCompartments(EnumSet.allOf(Compartment.class));
        alphaFieldContainer.setLevels(EnumSet.noneOf(Level.class));
        alphaFieldContainer.setGroups(EnumSet.allOf(Group.class));
        alphaField.setMarkings(alphaFieldContainer);
        fields.put(alphaKey, alphaField);

        SecurityContainer betaFieldContainer = new SecurityContainer();
        betaFieldContainer.setCompartments(EnumSet.allOf(Compartment.class));
        betaFieldContainer.setLevels(EnumSet.of(Level.SENSITIVE));
        betaFieldContainer.setGroups(EnumSet.allOf(Group.class));
        betaField.setMarkings(betaFieldContainer);
        fields.put(betaKey, betaField);

        document.setFields(fields);
        document.setOverallMarkings(dataContainer);
        List<ProtectedDocument> documents = new LinkedList<>();
        documents.add(document);
        assertEquals(1, handler.authorize(user,documents).size());
        assertEquals("some value",documents.get(0).getFields().get(alphaKey).getValue());
        assertNull(documents.get(0).getFields().get(betaKey).getValue());

    }

    @Test
    public void processUserWithPublic_DataHasNoLevels_FieldHasNoLevels() throws Exception{
                userContainer.setCompartments(EnumSet.allOf(Compartment.class)); 
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
                userContainer.setCompartments(EnumSet.allOf(Compartment.class)); 
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
                userContainer.setCompartments(EnumSet.allOf(Compartment.class)); 
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
                userContainer.setCompartments(EnumSet.allOf(Compartment.class)); 
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
                userContainer.setCompartments(EnumSet.allOf(Compartment.class)); 
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
                userContainer.setCompartments(EnumSet.allOf(Compartment.class)); 
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
                userContainer.setCompartments(EnumSet.allOf(Compartment.class)); 
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
                userContainer.setCompartments(EnumSet.allOf(Compartment.class)); 
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
                userContainer.setCompartments(EnumSet.allOf(Compartment.class)); 
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
                userContainer.setCompartments(EnumSet.allOf(Compartment.class)); 
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
                userContainer.setCompartments(EnumSet.allOf(Compartment.class)); 
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
                userContainer.setCompartments(EnumSet.allOf(Compartment.class)); 
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
                userContainer.setCompartments(EnumSet.allOf(Compartment.class)); 
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
                userContainer.setCompartments(EnumSet.allOf(Compartment.class)); 
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
                userContainer.setCompartments(EnumSet.allOf(Compartment.class)); 
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


    @Test
    public void processUserWithITGroup_DataHasHR() throws Exception{
                userContainer.setCompartments(EnumSet.allOf(Compartment.class)); 
        userContainer.setLevels(EnumSet.of(Level.SENSITIVE,Level.PUBLIC));
        userContainer.setGroups(EnumSet.of(Group.IT));
        user.setPermissions(userContainer);
        dataContainer.setCompartments(EnumSet.allOf(Compartment.class));
        dataContainer.setLevels(EnumSet.of(Level.SENSITIVE));
        dataContainer.setGroups(EnumSet.of(Group.HR));
        alphaField.setMarkings(dataContainer);
        fields.put(alphaKey,alphaField);
        document.setFields(fields);
        document.setOverallMarkings(dataContainer);
        List<ProtectedDocument> documents = new LinkedList<>();
        documents.add(document);
        assertEquals(0, handler.authorize(user,documents).size());
    }


    @Test
    public void processUserWithITGroup_DataHasNone() throws Exception{
                userContainer.setCompartments(EnumSet.allOf(Compartment.class)); 
        userContainer.setLevels(EnumSet.of(Level.SENSITIVE,Level.PUBLIC));
        userContainer.setGroups(EnumSet.of(Group.IT));
        user.setPermissions(userContainer);
        dataContainer.setCompartments(EnumSet.allOf(Compartment.class));
        dataContainer.setLevels(EnumSet.of(Level.SENSITIVE));
        dataContainer.setGroups(EnumSet.noneOf(Group.class));
        alphaField.setMarkings(dataContainer);
        fields.put(alphaKey,alphaField);
        document.setFields(fields);
        document.setOverallMarkings(dataContainer);
        List<ProtectedDocument> documents = new LinkedList<>();
        documents.add(document);
        assertEquals(1, handler.authorize(user,documents).size());
    }

    @Test
    public void processUserWithITGroup_DataHasIT() throws Exception{
                userContainer.setCompartments(EnumSet.allOf(Compartment.class)); 
        userContainer.setLevels(EnumSet.of(Level.SENSITIVE,Level.PUBLIC));
        userContainer.setGroups(EnumSet.of(Group.IT));
        user.setPermissions(userContainer);
        dataContainer.setCompartments(EnumSet.allOf(Compartment.class));
        dataContainer.setLevels(EnumSet.of(Level.SENSITIVE));
        dataContainer.setGroups(EnumSet.of(Group.IT));
        alphaField.setMarkings(dataContainer);
        fields.put(alphaKey,alphaField);
        document.setFields(fields);
        document.setOverallMarkings(dataContainer);
        List<ProtectedDocument> documents = new LinkedList<>();
        documents.add(document);
        assertEquals(1, handler.authorize(user,documents).size());
    }

    @Test
    public void processUserWithNoGroups_DataHasHR() throws Exception{
                userContainer.setCompartments(EnumSet.allOf(Compartment.class)); 
        userContainer.setLevels(EnumSet.of(Level.SENSITIVE,Level.PUBLIC));
        userContainer.setGroups(EnumSet.noneOf(Group.class));
        user.setPermissions(userContainer);
        dataContainer.setCompartments(EnumSet.allOf(Compartment.class));
        dataContainer.setLevels(EnumSet.of(Level.SENSITIVE));
        dataContainer.setGroups(EnumSet.of(Group.HR));
        alphaField.setMarkings(dataContainer);
        fields.put(alphaKey,alphaField);
        document.setFields(fields);
        document.setOverallMarkings(dataContainer);
        List<ProtectedDocument> documents = new LinkedList<>();
        documents.add(document);
        assertEquals(0, handler.authorize(user,documents).size());
    }

    @Test
    public void processUserWithNoGroups_DataHasNone() throws Exception{
                userContainer.setCompartments(EnumSet.allOf(Compartment.class)); 
        userContainer.setLevels(EnumSet.of(Level.SENSITIVE,Level.PUBLIC));
        userContainer.setGroups(EnumSet.noneOf(Group.class));
        user.setPermissions(userContainer);
        dataContainer.setCompartments(EnumSet.allOf(Compartment.class));
        dataContainer.setLevels(EnumSet.of(Level.SENSITIVE));
        dataContainer.setGroups(EnumSet.noneOf(Group.class));
        alphaField.setMarkings(dataContainer);
        fields.put(alphaKey,alphaField);
        document.setFields(fields);
        document.setOverallMarkings(dataContainer);
        List<ProtectedDocument> documents = new LinkedList<>();
        documents.add(document);
        assertEquals(1, handler.authorize(user,documents).size());
    }

    @Test
    public void processUserWithNoGroups_DataHasIT() throws Exception{
                userContainer.setCompartments(EnumSet.allOf(Compartment.class)); 
        userContainer.setLevels(EnumSet.of(Level.SENSITIVE,Level.PUBLIC));
        userContainer.setGroups(EnumSet.noneOf(Group.class));
        user.setPermissions(userContainer);
        dataContainer.setCompartments(EnumSet.allOf(Compartment.class));
        dataContainer.setLevels(EnumSet.of(Level.SENSITIVE));
        dataContainer.setGroups(EnumSet.of(Group.IT));
        alphaField.setMarkings(dataContainer);
        fields.put(alphaKey,alphaField);
        document.setFields(fields);
        document.setOverallMarkings(dataContainer);
        List<ProtectedDocument> documents = new LinkedList<>();
        documents.add(document);
        assertEquals(0, handler.authorize(user,documents).size());
    }


    @Test
    public void processUserWithHRGroup_DataHasNone() throws Exception{
                userContainer.setCompartments(EnumSet.allOf(Compartment.class)); 
        userContainer.setLevels(EnumSet.of(Level.SENSITIVE,Level.PUBLIC));
        userContainer.setGroups(EnumSet.of(Group.HR));
        user.setPermissions(userContainer);
        dataContainer.setCompartments(EnumSet.allOf(Compartment.class));
        dataContainer.setLevels(EnumSet.of(Level.SENSITIVE));
        dataContainer.setGroups(EnumSet.noneOf(Group.class));
        alphaField.setMarkings(dataContainer);
        fields.put(alphaKey,alphaField);
        document.setFields(fields);
        document.setOverallMarkings(dataContainer);
        List<ProtectedDocument> documents = new LinkedList<>();
        documents.add(document);
        assertEquals(1, handler.authorize(user,documents).size());
    }

    @Test
    public void processUserWithHRGroup_DataHasIT() throws Exception{
                userContainer.setCompartments(EnumSet.allOf(Compartment.class)); 
        userContainer.setLevels(EnumSet.of(Level.SENSITIVE,Level.PUBLIC));
        userContainer.setGroups(EnumSet.of(Group.HR));
        user.setPermissions(userContainer);
        dataContainer.setCompartments(EnumSet.allOf(Compartment.class));
        dataContainer.setLevels(EnumSet.of(Level.SENSITIVE));
        dataContainer.setGroups(EnumSet.of(Group.IT));
        alphaField.setMarkings(dataContainer);
        fields.put(alphaKey,alphaField);
        document.setFields(fields);
        document.setOverallMarkings(dataContainer);
        List<ProtectedDocument> documents = new LinkedList<>();
        documents.add(document);
        assertEquals(0, handler.authorize(user,documents).size());
    }

    @Test
    public void processUserWithHRGroup_DataHasHR() throws Exception{
                userContainer.setCompartments(EnumSet.allOf(Compartment.class)); 
        userContainer.setLevels(EnumSet.of(Level.SENSITIVE,Level.PUBLIC));
        userContainer.setGroups(EnumSet.of(Group.HR));
        user.setPermissions(userContainer);
        dataContainer.setCompartments(EnumSet.allOf(Compartment.class));
        dataContainer.setLevels(EnumSet.of(Level.SENSITIVE));
        dataContainer.setGroups(EnumSet.of(Group.HR));
        alphaField.setMarkings(dataContainer);
        fields.put(alphaKey,alphaField);
        document.setFields(fields);
        document.setOverallMarkings(dataContainer);
        List<ProtectedDocument> documents = new LinkedList<>();
        documents.add(document);
        assertEquals(1, handler.authorize(user,documents).size());
    }

    @Test
    public void processUserWithHRGroup_DataHasHRAndIT() throws Exception{
                userContainer.setCompartments(EnumSet.allOf(Compartment.class)); 
        userContainer.setLevels(EnumSet.of(Level.SENSITIVE,Level.PUBLIC));
        userContainer.setGroups(EnumSet.of(Group.HR));
        user.setPermissions(userContainer);
        dataContainer.setCompartments(EnumSet.allOf(Compartment.class));
        dataContainer.setLevels(EnumSet.of(Level.SENSITIVE));
        dataContainer.setGroups(EnumSet.of(Group.HR,Group.IT));
        alphaField.setMarkings(dataContainer);
        fields.put(alphaKey,alphaField);
        document.setFields(fields);
        document.setOverallMarkings(dataContainer);
        List<ProtectedDocument> documents = new LinkedList<>();
        documents.add(document);
        assertEquals(1, handler.authorize(user,documents).size());
    }

    @Test
    public void processUserWithITGroup_DataHasHRAndIT() throws Exception{
                userContainer.setCompartments(EnumSet.allOf(Compartment.class)); 
        userContainer.setLevels(EnumSet.of(Level.SENSITIVE,Level.PUBLIC));
        userContainer.setGroups(EnumSet.of(Group.IT));
        user.setPermissions(userContainer);
        dataContainer.setCompartments(EnumSet.allOf(Compartment.class));
        dataContainer.setLevels(EnumSet.of(Level.SENSITIVE));
        dataContainer.setGroups(EnumSet.of(Group.HR,Group.IT));
        alphaField.setMarkings(dataContainer);
        fields.put(alphaKey,alphaField);
        document.setFields(fields);
        document.setOverallMarkings(dataContainer);
        List<ProtectedDocument> documents = new LinkedList<>();
        documents.add(document);
        assertEquals(1, handler.authorize(user,documents).size());
    }


    @Test
    public void processUserWithIT_DataHasNoLevels_MultipleFieldsHaveDifferingValues() throws Exception{
        userContainer.setCompartments(EnumSet.allOf(Compartment.class));
        userContainer.setLevels(EnumSet.of(Level.PUBLIC));
        userContainer.setGroups(EnumSet.of(Group.IT));
        user.setPermissions(userContainer);
        dataContainer.setCompartments(EnumSet.allOf(Compartment.class));
        dataContainer.setLevels(EnumSet.noneOf(Level.class));
        dataContainer.setGroups(EnumSet.allOf(Group.class));

        SecurityContainer alphaFieldContainer = new SecurityContainer();
        alphaFieldContainer.setCompartments(EnumSet.allOf(Compartment.class));
        alphaFieldContainer.setLevels(EnumSet.noneOf(Level.class));
        alphaFieldContainer.setGroups(EnumSet.of(Group.IT));
        alphaField.setMarkings(alphaFieldContainer);
        fields.put(alphaKey, alphaField);

        SecurityContainer betaFieldContainer = new SecurityContainer();
        betaFieldContainer.setCompartments(EnumSet.allOf(Compartment.class));
        betaFieldContainer.setLevels(EnumSet.noneOf(Level.class));
        betaFieldContainer.setGroups(EnumSet.of(Group.HR));
        betaField.setMarkings(betaFieldContainer);
        fields.put(betaKey, betaField);

        document.setFields(fields);
        document.setOverallMarkings(dataContainer);
        List<ProtectedDocument> documents = new LinkedList<>();
        documents.add(document);
        assertEquals(1, handler.authorize(user,documents).size());
        assertEquals("some value",documents.get(0).getFields().get(alphaKey).getValue());
        assertNull(documents.get(0).getFields().get(betaKey).getValue());

    }

    @Test
    public void processUserWithIT_DataHasNoLevels_FieldHasITAndHR() throws Exception{
                userContainer.setCompartments(EnumSet.allOf(Compartment.class)); 
        userContainer.setLevels(EnumSet.of(Level.PUBLIC));
        userContainer.setGroups(EnumSet.of(Group.HR));
        user.setPermissions(userContainer);
        dataContainer.setCompartments(EnumSet.allOf(Compartment.class));
        dataContainer.setLevels(EnumSet.noneOf(Level.class));
        dataContainer.setGroups(EnumSet.allOf(Group.class));
        SecurityContainer fieldContainer = new SecurityContainer();
        fieldContainer.setCompartments(EnumSet.allOf(Compartment.class));
        fieldContainer.setLevels(EnumSet.noneOf(Level.class));
        fieldContainer.setGroups(EnumSet.of(Group.IT,Group.HR));
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
    public void processUserWithIT_DataHasNoLevels_FieldHasHR() throws Exception{
                userContainer.setCompartments(EnumSet.allOf(Compartment.class)); 
        userContainer.setLevels(EnumSet.of(Level.PUBLIC));
        userContainer.setGroups(EnumSet.of(Group.IT));
        user.setPermissions(userContainer);
        dataContainer.setCompartments(EnumSet.allOf(Compartment.class));
        dataContainer.setLevels(EnumSet.noneOf(Level.class));
        dataContainer.setGroups(EnumSet.noneOf(Group.class));
        SecurityContainer fieldContainer = new SecurityContainer();
        fieldContainer.setCompartments(EnumSet.allOf(Compartment.class));
        fieldContainer.setLevels(EnumSet.noneOf(Level.class));
        fieldContainer.setGroups(EnumSet.of(Group.HR));
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
    public void processUserWithIT_DataHasNoLevels_FieldHasIT() throws Exception{
                userContainer.setCompartments(EnumSet.allOf(Compartment.class)); 
        userContainer.setLevels(EnumSet.of(Level.PUBLIC));
        userContainer.setGroups(EnumSet.of(Group.IT));
        user.setPermissions(userContainer);
        dataContainer.setCompartments(EnumSet.allOf(Compartment.class));
        dataContainer.setLevels(EnumSet.noneOf(Level.class));
        dataContainer.setGroups(EnumSet.noneOf(Group.class));
        SecurityContainer fieldContainer = new SecurityContainer();
        fieldContainer.setCompartments(EnumSet.allOf(Compartment.class));
        fieldContainer.setLevels(EnumSet.noneOf(Level.class));
        fieldContainer.setGroups(EnumSet.of(Group.IT));
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
    public void processUserWithIT_DataHasNoGroups_FieldHasNone() throws Exception{
                userContainer.setCompartments(EnumSet.allOf(Compartment.class)); 
        userContainer.setLevels(EnumSet.of(Level.PUBLIC));
        userContainer.setGroups(EnumSet.of(Group.IT));
        user.setPermissions(userContainer);
        dataContainer.setCompartments(EnumSet.allOf(Compartment.class));
        dataContainer.setLevels(EnumSet.noneOf(Level.class));
        dataContainer.setGroups(EnumSet.noneOf(Group.class));
        SecurityContainer fieldContainer = new SecurityContainer();
        fieldContainer.setCompartments(EnumSet.allOf(Compartment.class));
        fieldContainer.setLevels(EnumSet.noneOf(Level.class));
        fieldContainer.setGroups(EnumSet.noneOf(Group.class));
        alphaField.setMarkings(fieldContainer);
        fields.put(alphaKey, alphaField);
        document.setFields(fields);
        document.setOverallMarkings(dataContainer);
        List<ProtectedDocument> documents = new LinkedList<>();
        documents.add(document);
        assertEquals(1, handler.authorize(user,documents).size());
        assertEquals("some value",documents.get(0).getFields().get(alphaKey).getValue());
    }
}