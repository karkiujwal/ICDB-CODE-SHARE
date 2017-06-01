package verify;

import crypto.AlgorithmType;
import crypto.CodeGen;
import com.google.common.base.Charsets;
import com.google.common.base.Stopwatch;
import crypto.signer.RSASHA1Signer;
import io.DBConnection;
import io.Format;
import io.source.DBSource;
import io.source.DataSource;
import main.ICDBTool;
import main.args.config.UserConfig;
import main.args.option.Granularity;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3;
import org.bouncycastle.jcajce.provider.digest.SHA3.Digest256;

import java.io.File;
import java.security.MessageDigest;

import org.bouncycastle.util.encoders.Hex;
import org.jooq.*;
import parse.ICDBQuery;
import stats.RunStatistics;
import stats.Statistics;
import verify.serial.AbstractIcrl;
import verify.serial.Icrl;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.text.DecimalFormat;
import java.util.*;
import java.util.concurrent.*;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;


/**
 * <p>
 *     Verifies a SQL query
 * </p>
 * Created 5/8/2016
 * @author Dan Kondratyuk
 */
public abstract class QueryVerifier {

    protected final DBConnection icdb;
    private final  UserConfig userConfig;
    protected final CodeGen codeGen;
    protected crypto.Key key;

    public final AbstractIcrl icrl = Icrl.Companion.getIcrl();

    protected final DSLContext icdbCreate;
    protected final StringBuilder errorStatus = new StringBuilder();

    public final Map<String, Double> columnComputedValue=new ConcurrentHashMap<String, Double>();
    public final Map<String, Integer> avgOperationCount=new ConcurrentHashMap<String, Integer>();

    protected final List<Integer> testTotal= new ArrayList<>();
    protected final int threads;
    private final DataSource.Fetch fetch;
    protected final RunStatistics statistics;

    private static final Logger logger = LogManager.getLogger();

    protected Integer totalICSize=0;
    protected Integer totalDataSize=0;
    protected Integer totalSerialSize=0;

    protected BigInteger message = BigInteger.valueOf(1);
    protected BigInteger sig = BigInteger.valueOf(1);
    protected StringBuilder sigBuilderCloud = new StringBuilder();
    protected String AggSigCloud ;
    protected StringBuilder sigBuilderClient = new StringBuilder();
    protected String AggSigClient ;

    BigInteger finalClientSig=BigInteger.ONE;

    protected   String delimeter;



    public QueryVerifier(DBConnection icdb, UserConfig dbConfig, int threads, DataSource.Fetch fetch, RunStatistics statistics) {
        this.icdb = icdb;
        this.userConfig=dbConfig;
        this.codeGen = dbConfig.codeGen;
        this.threads = threads;
        this.fetch = fetch;
        this.statistics = statistics;
        key=codeGen.getKey();
        this.icdbCreate = icdb.getCreate();
        delimeter=",";
    }

    /**
     * Executes and verifies a given query
     * @return true if the query is verified
     */
    public boolean verify(ICDBQuery icdbQuery) {
        logger.debug("Using fetch type: {}", fetch);

        Stopwatch totalQueryVerificationTime = Stopwatch.createStarted();

        logger.info("Verify Query: {}", Format.limit(icdbQuery.getVerifyQuery()));

        Stopwatch queryFetchTime = Stopwatch.createStarted();
        Stream<Record> records = DBSource.stream(icdb, icdbQuery.getVerifyQuery(), fetch);
        statistics.setDataFetchTime(queryFetchTime.elapsed(ICDBTool.TIME_UNIT));
        logger.debug("Data fetch time: {}", statistics.getDataFetchTime());

        Stopwatch queryVerificationTime = Stopwatch.createStarted();
        //final verification if not AGGREGATE VERIFICATION or aggregate message generation if RSA_AGGREGATE or final Integrity Code Generation(on client) if MAC_AGGREGATE
        boolean verified = verifyRecords(records,  icdbQuery);
        records.close();
        //generate final IC for client if RSA_AGGREGATE
        if (codeGen.getAlgorithm()== AlgorithmType.RSA_AGGREGATE ){
            RSASHA1Signer signer=new RSASHA1Signer(key.getModulus(),key.getExponent());
            finalClientSig= new BigInteger(signer.computeRSA(message.toByteArray()));
        }
        statistics.setVerificationTime(queryVerificationTime.elapsed(ICDBTool.TIME_UNIT));


            //set total data and serial size (excluding IC)
            statistics.setTotalDataSize(totalDataSize);
            statistics.setTotalSerialSize(totalSerialSize);




        if (codeGen.getAlgorithm()== AlgorithmType.RSA_AGGREGATE  || codeGen.getAlgorithm()==AlgorithmType.AES_AGGREGATE || codeGen.getAlgorithm()==AlgorithmType.SHA_AGGREGATE  ){
            verified=verifyAggregate(icdbQuery);
        }

        //time to verify the query results, time to
        logger.debug("Data verification time/final message generation time(for ALGO_AGGREGATE): {}", statistics.getVerificationTime());
        logger.debug("Aggregate Query Fetch Time: {}", statistics.getAggregateRecordFetchTime());
        logger.debug("Aggregate Signature generation time: {}", statistics.getAggregateSigGenerationTime());
        logger.debug("Aggregate Final Verification time(microsec): {}", statistics.getAGG_final_verificationTime());
        //time to verify the query results, time to
        logger.debug("Data verification time/final message generation time(for ALGO_AGGREGATE): {}", statistics.getVerificationTime());
        logger.debug("Total query verification time: {}", totalQueryVerificationTime.elapsed(ICDBTool.TIME_UNIT));
        return verified;
    }


    public boolean verifyAggregate(ICDBQuery icdbQuery)  {
        boolean verified=false;
        //get the records (integrity codes) to generate final aggregate signature
        Stopwatch aggregateRecordFetchTime = Stopwatch.createStarted();
        Stream<Record> AggregateRecords = DBSource.stream(icdb, icdbQuery.getAggregateQuery(), fetch);
        statistics.setAggregateRecordFetchTime(aggregateRecordFetchTime.elapsed(ICDBTool.TIME_UNIT));

        //check for aggregate signature generated
        Stopwatch aggregateSigGenerationTime = Stopwatch.createStarted();
        boolean isAggregateSigGenerated=isAggregateSignatureGenerated(AggregateRecords,icdbQuery);
        //do final Hashing on the combined signatures for AES and SHA
        if (codeGen.getAlgorithm()== AlgorithmType.AES_AGGREGATE || codeGen.getAlgorithm()== AlgorithmType.SHA_AGGREGATE){
//            DigestSHA3 md = new DigestSHA3(256); //same as DigestSHA3 md = new SHA3.Digest256();
//            md.update(sigBuilderCloud.toString().getBytes(Charsets.UTF_8));
//            sigBuilderCloud.setLength(0);
//            AggSigCloud= Hex.toHexString(md.digest());
            MessageDigest md;
            try {
                 md = MessageDigest.getInstance("SHA-256");
                md.update(sigBuilderCloud.toString().getBytes(Charsets.UTF_8));
                sigBuilderCloud.setLength(0);
                AggSigCloud= Hex.toHexString(md.digest());

            } catch (NoSuchAlgorithmException ex) {
                System.out.println(ex.getMessage());
            }

             // AggSigCloud=Hex.toHexString(codeGen.generateSignature(sigBuilderCloud.toString().getBytes(Charsets.UTF_8)));
        }
        statistics.setAggregateSigGenerationTime(aggregateSigGenerationTime.elapsed(ICDBTool.TIME_UNIT));




        //track the time for AggregateFinalVerification
        Stopwatch aggregateFinalVerificationTime = Stopwatch.createStarted();
        if(isAggregateSigGenerated && codeGen.getAlgorithm()== AlgorithmType.RSA_AGGREGATE ){
            if(Arrays.equals(finalClientSig.toByteArray(),sig.toByteArray())) {
                logger.info("ICDB aggregate sign verified");
                verified = true;
            }


        }else if(isAggregateSigGenerated){
            //track the time for MAC_AGGREGATE final verification
            //do final  hashing on the combination of signatures regenerated by the client
            /*
            DigestSHA3 md1 = new DigestSHA3(256); //same as DigestSHA3 md = new SHA3.Digest256();
            md1.update(sigBuilderClient.toString().getBytes(Charsets.UTF_8));
            sigBuilderClient.setLength(0);
            */


          //  AggSigClient=Hex.toHexString(codeGen.generateSignature(sigBuilderClient.toString().getBytes(Charsets.UTF_8)));

            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(sigBuilderClient.toString().getBytes(Charsets.UTF_8));
                sigBuilderClient.setLength(0);
                AggSigClient= Hex.toHexString(md.digest());

            } catch (NoSuchAlgorithmException ex) {
                System.out.println(ex.getMessage());
            }

            if (AggSigCloud.equals(AggSigClient))
                 verified=true;


        }else{
            logger.error("Aggregate Signature not generated");
        }
        //set total IC size
        statistics.setTotalICSize(totalICSize);
        //Note: the millisec value for RSA final aggregate verification gave a 'long' value of 0, to keep the exact record, micro sec is used
        statistics.setAGG_final_verificationTime(aggregateFinalVerificationTime.elapsed(TimeUnit.MICROSECONDS));

        return verified;
    }

    public void execute(ICDBQuery icdbQuery) {


        if (icdbQuery.isAggregateQuery) {
            //compute aggregate average operation if any
            Stopwatch aggregateQueryExecutionTime = Stopwatch.createStarted();
            if (avgOperationCount.size()!=0){
                avgOperationCount.entrySet().forEach(entry-> {
                    DecimalFormat df = new DecimalFormat("#.0000");
                    columnComputedValue.put(entry.getKey(),Double.valueOf(df.format(columnComputedValue.get(entry.getKey())/entry.getValue())));
                    logger.debug("aggregate operation value: {}",columnComputedValue.get(entry.getKey()) );
                        }
                );
            }

           if (icdbQuery.executeandmatch(icdbCreate,columnComputedValue)){
            logger.info("aggregate operation matched");
               logger.debug("Total Aggregate Operation time: {}", statistics.getAggregateOperationTime());
               logger.debug("Aggregate query execution and match Time: {}", aggregateQueryExecutionTime.elapsed(ICDBTool.TIME_UNIT));

           }
        }else{

            Stopwatch queryExecutionTime = Stopwatch.createStarted();

            icdbQuery.execute(icdbCreate);

            statistics.setExecutionTime(queryExecutionTime.elapsed(ICDBTool.TIME_UNIT));
            logger.debug("Total query execution time: {}", statistics.getExecutionTime());

            // Add all pending serials
            icrl.commit();

            // Revoke all pending serials
            if (!icdbQuery.serialsToBeRevoked.isEmpty()) {
                icdbQuery.serialsToBeRevoked.forEach(serial -> icrl.revoke(serial));
                icdbQuery.serialsToBeRevoked.clear();
            }
        }


    }


    protected long verifyCount = 0;
    /**
     * Executes and verifies a given query given a cursor into the data records
     * @return true if the query is verified
     */
    private boolean verifyRecords(Stream<Record> records, ICDBQuery icdbQuery) {

        //backup optimizatio code (for adding attrname and table name to data value)
//        if(userConfig.granularity== Granularity.FIELD){
//
//            Optional<Record> Optrecord=records.findFirst();
//            //record.toString();
//            List<String> tables=new ArrayList<>();
//            List<String> attributeNames=new ArrayList<>();
//            Record record= Optrecord.get();
//            for (Field field:record.fields()) {
//                System.out.println(field.toString());
//                    tables.add(field.toString().split("\\.")[0].replace("\"", ""));
//                    attributeNames.add(field.toString().split("\\.")[1].replace("\"", "").toLowerCase());
//            }
//            icdbQuery.tables=tables;
//            icdbQuery.attributeNames=attributeNames;
//
//        }
        final ForkJoinPool threadPool = threads < 1 ? new ForkJoinPool() : new ForkJoinPool(threads);

        logger.debug("Using {} thread(s)", threadPool.getParallelism());
        verifyCount = 0;
        List<CompletableFuture<Boolean>> futures;
        if (codeGen.getAlgorithm()== AlgorithmType.RSA_AGGREGATE || codeGen.getAlgorithm()== AlgorithmType.AES_AGGREGATE || codeGen.getAlgorithm()== AlgorithmType.SHA_AGGREGATE){
            futures = records.map(record -> CompletableFuture.supplyAsync(() -> aggregateVerifyRecord(record, icdbQuery), threadPool))
                    .collect(Collectors.toList());
        }else {
            futures = records.map(record -> CompletableFuture.supplyAsync(() -> verifyRecord(record, icdbQuery), threadPool))
                    .collect(Collectors.toList());
        }

        // Asynchronously verify all signatures
        return futures.stream()
            .allMatch(f -> {
                try {
                    statistics.setQueryFetchSize(++verifyCount);
                    return f.get();
                } catch (InterruptedException | ExecutionException e) {
                    throw new RuntimeException(e);
                }
            });
    }

    /**
     * Hints the completion of Aggregate Sign Generation
     * @return true if Agg Sign generated
     */
    private boolean isAggregateSignatureGenerated(Stream<Record> records, ICDBQuery icdbQuery) {
        final ForkJoinPool threadPool = threads < 1 ? new ForkJoinPool() : new ForkJoinPool(threads);

        logger.debug("Using {} thread(s)", threadPool.getParallelism());
        verifyCount = 0;
        List<CompletableFuture<Boolean>> futures;
        if (codeGen.getAlgorithm()== AlgorithmType.RSA_AGGREGATE ){
            futures=records.map(record -> CompletableFuture.supplyAsync(() -> aggregateRSASignatureGenerator(record, icdbQuery), threadPool))
                    .collect(Collectors.toList());
        }else{
            //if HMAC or CMAC
            futures=records.map(record -> CompletableFuture.supplyAsync(() -> aggregateMACSignatureGenerator(record, icdbQuery), threadPool))
                    .collect(Collectors.toList());

        }


        // Asynchronously verify all signatures
        return futures.stream()
                .allMatch(f -> {
                    try {
                        statistics.setQueryFetchSize(++verifyCount);
                        return f.get();
                    } catch (InterruptedException | ExecutionException e) {
                        throw new RuntimeException(e);
                    }
                });
    }

    protected abstract boolean verifyRecord(Record record, ICDBQuery icdbQuery);

    //verification by using RSA homomorphic multiplication
    protected abstract boolean aggregateVerifyRecord(Record record, ICDBQuery icdbQuery) ;



    /**
     * Verifies data and serial number by regenerating the signature
     * @param serial the serial number
     * @param signature the original signature
     * @param data the data to verify
     * @return true if the regenerated signature matches the original signature
     */
    protected boolean verifyData(final long serial, final byte[] signature, final String data) {
        final byte[] serialBytes = ByteBuffer.allocate(8).putLong(serial).array();
        final byte[] dataBytes = data.getBytes(Charsets.UTF_8);

        final byte[] allBytes = ArrayUtils.addAll(dataBytes, serialBytes);

        final boolean serialVerified = icrl.contains(serial);
        final boolean signatureVerified = codeGen.verify(allBytes, signature);
        return serialVerified && signatureVerified;
    }

    /**
     * regenerate serial on the client machine to combine and compute final aggregate IC
     * @param serial
     * @param data
     * @return
     */
    protected byte[] regenerateSignature(final long serial,  final String data) {
        final byte[] serialBytes = ByteBuffer.allocate(8).putLong(serial).array();
        final byte[] dataBytes = data.getBytes(Charsets.UTF_8);

        final byte[] allBytes = ArrayUtils.addAll(dataBytes, serialBytes);
       // totalDataSize+=dataBytes.length;
        totalSerialSize+=serialBytes.length;

            return codeGen.generateSignature(allBytes);

    }


    /**
     * generates the final aggregate signature by homomorphic multiplication of each of column_ic
     * @param record
     * @param icdbQuery
     * @return
     */
    protected boolean aggregateRSASignatureGenerator(Record record, ICDBQuery icdbQuery) {

        final StringBuilder builder = new StringBuilder();

        int index = 0;
        for (Field<?> attr : record.fields()) {

            final byte[] signature = (byte[]) record.get(index);
            totalICSize+=signature.length;
            sig = sig.multiply(new BigInteger(signature)).mod(key.getModulus());

            index++;
        }
        return true;
    }

    /**
     * generates the final aggregate signature by combining all the column_ic and hashing
     * @param record
     * @param icdbQuery
     * @return
     */
    protected boolean aggregateMACSignatureGenerator(Record record, ICDBQuery icdbQuery) {

        int index = 0;
        for (Field<?> attr : record.fields()) {

             byte[] signature = (byte[]) record.get(index);
            totalICSize+=signature.length;
            sigBuilderCloud.append(Hex.toHexString(signature));
          //  sig = sig.multiply(new BigInteger(signature)).mod(key.getModulus());
            index++;
        }
        return true;

    }



    /**
     * @return An error message, if it exists
     */
    public String getError() {
        return errorStatus.toString();
    }


    protected void computeAggregateOperation(ICDBQuery icdbQuery,Record record){
        icdbQuery.columnOperation.entrySet().forEach(entry -> {
            String ColumnName=((String) entry.getKey()).substring(((String)entry.getKey()).indexOf("(") + 1, ((String)entry.getKey()).indexOf(")"));
            if (entry.getValue().equalsIgnoreCase("SUM")){
                operateSum(record,entry,ColumnName);
            }else if (entry.getValue().equalsIgnoreCase("MAX")){
                operateMax(record,entry,ColumnName);
            }else if (entry.getValue().equalsIgnoreCase("MIN")){
                operateMin(record,entry,ColumnName);
            }else if (entry.getValue().equalsIgnoreCase("AVG")){
                operateAvg(record,entry,ColumnName);
            }else if (entry.getValue().equalsIgnoreCase("COUNT")){
                operateCount((String)entry.getKey());
            }
        });
    }

    protected void operateSum(Record record, Map.Entry entry,String ColumnName){
        if (columnComputedValue.get(entry.getKey())!=null){
            Double oldValue=columnComputedValue.get(entry.getKey());
            columnComputedValue.put((String)entry.getKey(),oldValue+ ((Integer)record.get(ColumnName)).doubleValue());
        }else {
            columnComputedValue.put((String)entry.getKey(), ((Integer)record.get(ColumnName)).doubleValue());
        }
    }

    protected void operateMax(Record record, Map.Entry entry,String ColumnName){

        if (columnComputedValue.get(entry.getKey())!=null){
            Double oldValue=columnComputedValue.get((String)entry.getKey());
            if (Double.parseDouble(record.get(ColumnName).toString()) > oldValue) {
                columnComputedValue.put((String)entry.getKey(),((Integer)record.get(ColumnName)).doubleValue());
            }

        }else {
            columnComputedValue.put((String)entry.getKey(), ((Integer)record.get(ColumnName)).doubleValue());
        }
    }

    protected void operateMin(Record record, Map.Entry entry,String ColumnName){

        if (columnComputedValue.get(entry.getKey())!=null){
            Double oldValue=columnComputedValue.get((String)entry.getKey());
            if (Double.parseDouble(record.get(ColumnName).toString()) < oldValue) {
                columnComputedValue.put((String)entry.getKey(), ((Integer)record.get(ColumnName)).doubleValue());
            }

        }else {
            columnComputedValue.put((String)entry.getKey(), ((Integer)record.get(ColumnName)).doubleValue());
        }
    }

    protected void operateAvg(Record record, Map.Entry entry,String ColumnName){

        if (columnComputedValue.get(entry.getKey())!=null){
            Double oldValue=columnComputedValue.get((String)entry.getKey());
            columnComputedValue.put((String)entry.getKey(), ((((Integer)record.get(ColumnName)).doubleValue())+oldValue));

        }else {
            columnComputedValue.put((String)entry.getKey(),  ((Integer)record.get(ColumnName)).doubleValue());
        }
        //count the total operation for avg calculation
        if (avgOperationCount.get(entry.getKey())==null)
            avgOperationCount.put((String)entry.getKey(),1);
        else
            avgOperationCount.put((String)entry.getKey(),avgOperationCount.get((String)entry.getKey())+1);
    }

    protected void operateCount(String computedkey){
        if (columnComputedValue.get(computedkey)!=null){
            columnComputedValue.put(computedkey, columnComputedValue.get(computedkey) + 1.0);
        }else {
            columnComputedValue.put(computedkey, 1.0);
        }
    }
//
}
