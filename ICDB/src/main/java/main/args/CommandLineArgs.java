package main.args;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.Reader;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.google.gson.Gson;

import main.args.config.ConfigArgs;
import main.args.option.ReaderConverter;

/**
 * A class to create an instance of dirrent types of command as convertion of query, execution of query, benchmarking, conversion of database
 */
public class CommandLineArgs {

    public static final String CONVERT_DB = "convert-db";
    public static final String CONVERT_QUERY = "convert-query";
    public static final String EXECUTE_QUERY = "execute-query";
    public static final String EXECUTE_QUERY_SINGLE_BENCHMARK = "execute-query-benchmark";
    public static final String BENCHMARK = "benchmark";

    public final JCommander jCommander;

    public final ConvertDBCommand convertDBCommand;
    public final ConvertQueryCommand convertQueryCommand;
    public final ExecuteQueryCommand executeQueryCommand;
    public final MultirunBenchmarkCommand multirunbenchmarkCommand;
    public final BenchmarkCommand benchmarkCommand;



    @Parameter(names = {"-c", "--config"}, converter = ReaderConverter.class, description = "The path of the JSON configuration file")
    public Reader readerConfig = new FileReader("config.json");

    private ConfigArgs config;

    public CommandLineArgs(String[] args) throws FileNotFoundException {

        jCommander = new JCommander(this);

        convertDBCommand = new ConvertDBCommand();
        convertQueryCommand = new ConvertQueryCommand();
        executeQueryCommand = new ExecuteQueryCommand();
        benchmarkCommand = new BenchmarkCommand();
        multirunbenchmarkCommand= new MultirunBenchmarkCommand();

        jCommander.addCommand(convertDBCommand);
        jCommander.addCommand(convertQueryCommand);
        jCommander.addCommand(executeQueryCommand);
        jCommander.addCommand(benchmarkCommand);
        jCommander.addCommand(multirunbenchmarkCommand);

        try {
            jCommander.parse(args);
        } catch (Exception e) {
            System.err.println(e.getMessage());
            System.exit(1);
        }

        Gson gson = new Gson();
        config = gson.fromJson(readerConfig, ConfigArgs.class);
    }

    public ConfigArgs getConfig() {
        return config;
    }

    public boolean isCommand(String command) {
        String parsedCommand = jCommander.getParsedCommand();
        return parsedCommand != null && parsedCommand.equals(command);
    }

}
