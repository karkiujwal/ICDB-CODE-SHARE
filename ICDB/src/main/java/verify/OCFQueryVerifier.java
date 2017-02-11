package verify;

import com.google.common.base.Charsets;
import com.google.common.base.Stopwatch;
import crypto.AlgorithmType;
import crypto.signer.RSASHA1Signer;
import io.DBConnection;
import io.source.DataSource;
import main.ICDBTool;
import main.args.config.UserConfig;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.jooq.Field;
import org.jooq.Record;
import parse.ICDBQuery;
import stats.RunStatistics;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * <p>
 *      Executes an OCF query and verifies data integrity
 * </p>
 * Created on 7/16/2016
 *
 * @author Dan Kondratyuk
 */
public class OCFQueryVerifier extends QueryVerifier {

    private static final Logger logger = LogManager.getLogger();


    public OCFQueryVerifier(DBConnection icdb, UserConfig dbConfig, int threads, DataSource.Fetch fetch, RunStatistics statistics) {
        super(icdb, dbConfig, threads, fetch, statistics);
    }

    @Override
    protected boolean verifyRecord(Record record, ICDBQuery icdbQuery) {
        final int dataSize = record.size() / 3;
        List<String> tableList=icdbQuery.queryTableName;

        for (int i = 0; i < dataSize; i++) {
            final long serial = (long) record.get(dataSize + 2 * i + 1);
            final byte[] signature = (byte[]) record.get(dataSize + 2 * i);
             String data = record.get(i).toString();

            //concat the primary keys values
            if (icdbQuery.isJoinQuery){
                //get table name from the record field name
                String table= record.field(i).toString().split("\\.")[0].replace("\"", "");
                List<String>primaryKeysList=icdb.getPrimaryKeys(table);
                //  Collections.sort(primaryKeysList, String.CASE_INSENSITIVE_ORDER);
                for (String primarykey:primaryKeysList) {
                    data=data.concat(record.get(primarykey).toString());
                }
            }else{
                List<String>primaryKeysList=icdb.getPrimaryKeys(tableList.get(0));
                //  Collections.sort(primaryKeysList, String.CASE_INSENSITIVE_ORDER);
                for (String primarykey:primaryKeysList) {
                    data=data.concat(record.get(primarykey).toString());
                }
            }



            //concat table name to the end
            if (icdbQuery.isJoinQuery){
                //get table name from the record field name
                String table= record.field(i).toString().split("\\.")[0].replace("\"", "");
                data=data.concat(table.toLowerCase());

            }else{
                data=data.concat(tableList.get(0));
            }



            final boolean verified = verifyData(serial, signature, data);

            if (!verified) {
                errorStatus.append("\n")
                        .append(record.field(i))
                        .append(" : ")
                        .append(record.get(i))
                        .append("\n");
                return false;
            }

            if (icdbQuery.isAggregateQuery && i==dataSize-1) {
                Stopwatch aggregateOperationTime = Stopwatch.createStarted();
                computeAggregateOperation(icdbQuery, record);
                statistics.setAggregateOperationTime( statistics.getAggregateOperationTime()+aggregateOperationTime.elapsed(ICDBTool.TIME_UNIT));
            }
        }

        return true;
    }

    /**
     * generaates aggregate value for the data(messages) to compute and verify final aggregate signature
     * @param record
     * @param icdbQuery
     * @return
     */
    @Override
    protected boolean aggregateVerifyRecord(Record record, ICDBQuery icdbQuery) {

        final int dataSize = record.size() / 2;
        List<String> tableList=icdbQuery.queryTableName;


        for (int i = 0; i < dataSize; i++) {

            final long serial = (long) record.get(dataSize + i);
          //  final byte[] signature = (byte[]) record.get(dataSize + 2 * i);
             String data = record.get(i).toString();
            totalDataSize+=data.getBytes().length;

            //concat the primary keys values
            if (icdbQuery.isJoinQuery){
                //get table name from the record field name
                String table= record.field(i).toString().split("\\.")[0].replace("\"", "");
                List<String>primaryKeysList=icdb.getPrimaryKeys(table);
                //  Collections.sort(primaryKeysList, String.CASE_INSENSITIVE_ORDER);
                for (String primarykey:primaryKeysList) {
                    data=data.concat(record.get(primarykey).toString());
                }
            }else{
                List<String>primaryKeysList=icdb.getPrimaryKeys(tableList.get(0));
                //  Collections.sort(primaryKeysList, String.CASE_INSENSITIVE_ORDER);
                for (String primarykey:primaryKeysList) {
                    data=data.concat(record.get(primarykey).toString());
                }
            }



            //concat table name to the end
            if (icdbQuery.isJoinQuery){
                //get table name from the record field name
                String table= record.field(i).toString().split("\\.")[0].replace("\"", "");
                data=data.concat(table.toLowerCase());

            }else{
                data=data.concat(tableList.get(0));
            }



            //check the ICRL
            if (!icrl.contains(serial)) {
                return false;
            }


            //generate aggregate message for RSA and regenerate signature for AES and SHA
            if (codeGen.getAlgorithm()== AlgorithmType.RSA_AGGREGATE){
                final byte[] dataBytes = data.getBytes(Charsets.UTF_8);

                // final String serialString = Long.toString(serial);
                final byte[] serialBytes = ByteBuffer.allocate(8).putLong(serial).array();

              //  totalDataSize+=dataBytes.length;
                totalSerialSize+=serialBytes.length;

                final byte[] allData = ArrayUtils.addAll(dataBytes, serialBytes);

                RSASHA1Signer signer=new RSASHA1Signer(key.getModulus(),key.getExponent());
                message = message.multiply(new BigInteger(signer.computehash(allData))).mod(key.getModulus());

            }else{
                sigBuilderClient.append(Hex.toHexString(regenerateSignature(serial,data)));
            }

            if (icdbQuery.isAggregateQuery && i==dataSize-1) {
                Stopwatch aggregateOperationTime = Stopwatch.createStarted();
                computeAggregateOperation(icdbQuery, record);
                statistics.setAggregateOperationTime( statistics.getAggregateOperationTime()+aggregateOperationTime.elapsed(ICDBTool.TIME_UNIT));
            }
        }


        return true;
    }






}
