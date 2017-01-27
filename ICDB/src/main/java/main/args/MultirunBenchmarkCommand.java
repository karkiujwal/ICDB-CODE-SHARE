package main.args;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import io.source.DataSource;

/**
 * <p>
 *     JCommander Command for executing an ICDB query
 * </p>
 * Created on 5/10/2016
 *
 * @author Dan Kondratyuk
 */
@Parameters(commandNames = { CommandLineArgs.EXECUTE_QUERY_SINGLE_BENCHMARK }, commandDescription = "Execute queries for a loop of 5 on an ICDB Schema")
public class MultirunBenchmarkCommand extends ConfigCommand {

    @Parameter(names = { "-q", "--query" }, description = "Execute a query as an argument")
    public String query;

    @Parameter(names = { "-C", "--convert" }, description = "Convert the query before executing")
    public Boolean convert = false;

    @Parameter(names = { "-f", "--fetch" }, description = "Use eager or lazy fetching. (Default: LAZY)")
    public DataSource.Fetch fetch = DataSource.Fetch.LAZY;

    @Parameter(names = { "-t", "--threads" }, description = "The number of worker threads for verification. An argument of 0 will use the JVM default configuration, which usually results in the best parallel performance. (Default: 0)")
    public Integer threads = 0;

}
