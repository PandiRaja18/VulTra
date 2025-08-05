import ai.onnxruntime.OnnxTensor;
import ai.onnxruntime.OrtEnvironment;
import ai.onnxruntime.OrtException;
import ai.onnxruntime.OrtSession;

public class EmailClassifier {

    private final static Logger LOGGER = Logger.getLogger(EmailClassifier.class.getName());

    private String modelPath;