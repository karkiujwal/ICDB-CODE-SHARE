package verify;

import com.google.common.base.Charsets;
import com.google.common.base.Stopwatch;
import com.google.common.math.BigIntegerMath;
import crypto.AlgorithmType;
import crypto.signer.RSASHA1Signer;
import io.DBConnection;
import io.Format;
import io.source.DataSource;
import main.ICDBTool;
import main.args.config.UserConfig;
import net.sf.jsqlparser.JSQLParserException;
import net.sf.jsqlparser.parser.CCJSqlParserManager;
import net.sf.jsqlparser.statement.Statement;
import net.sf.jsqlparser.statement.delete.Delete;
import net.sf.jsqlparser.statement.insert.Insert;
import net.sf.jsqlparser.statement.select.Select;
import net.sf.jsqlparser.statement.update.Update;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.util.encoders.Hex;
import org.jooq.Field;
import org.jooq.Record;
import stats.RunStatistics;

import parse.ICDBQuery;

import java.io.Reader;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.List;

/**
 * Executes an OCT query and verifies data integrity.
 *
 * Created on 7/16/2016
 * @author Dan Kondratyuk
 */
public class OCTQueryVerifier extends QueryVerifier {

    private final CCJSqlParserManager parserManager = new CCJSqlParserManager();
    public OCTQueryVerifier(DBConnection icdb, UserConfig dbConfig, int threads, DataSource.Fetch fetch, RunStatistics statistics) {
        super(icdb, dbConfig, threads, fetch, statistics);
    }

    public String getError() {
        return errorStatus.toString();
    }

    @Override
    protected boolean verifyRecord(Record record, ICDBQuery icdbQuery) {
        final StringBuilder builder = new StringBuilder();

        //   Field<?>[] Serial = record.fields(Format.SERIAL_COLUMN);
        //  Field<?> IC = record.field(Format.IC_COLUMN);

        int index = 0;
        boolean verified = false;
        boolean isSkip = false;
        List<String> tableList=icdbQuery.queryTableName;

        int tableIndex=0;
        for (Field<?> attr : record.fields()) {

            if (!attr.getName().equals("ic") && !attr.getName().equals("serial")) {
                final Object value = record.get(index);
                builder.append(value);
                builder.append(delimeter);

                index++;
                if (isSkip)
                    isSkip = false;

            } else {
                if (isSkip)
                    continue;

                final byte[] signature = (byte[]) record.get(index);
                final long serial = (long) record.get(index + 1);

                 String data = builder.toString();
                //concat table name to the end (OLD)
//                for (String table:tableList) {
//                    data=data.concat(table.toLowerCase());
//                }
                data=data.concat(tableList.get(tableIndex).toLowerCase());
                tableIndex++;

                verified = verifyData(serial, signature, data);

                builder.setLength(0);
                if (!verified) {
                    errorStatus.append("\n")
                            .append(record.toString())
                            .append("\n");
                    break;
                }

              //  if delete query, add the serials to be revoked in the list
                if (icdbQuery.isDeleteQuery)
                    icdbQuery.serialsToBeRevoked.add(serial);



                if (record.size() == index + 2)
                    break;
                else {
                    isSkip = true;
                    index += 2;
                }
            }
//(OLD)
//        final StringBuilder builder = new StringBuilder();
//
//        for (int i = 0; i < record.size() - 2; i++) {
//            final Object value = record.get(i);
//            builder.append(value);
//        }
//
//        final long serial = (long) record.get(Format.SERIAL_COLUMN);
//        final byte[] signature = (byte[]) record.get(Format.IC_COLUMN);
//        final String data = builder.toString();
//
//        final boolean verified = verifyData(serial, signature, data);
//
//        if (!verified) {
//            errorStatus.append("\n")
//                    .append(record.toString())
//                    .append("\n");
//        }

        }

        if (icdbQuery.isAggregateQuery) {
            Stopwatch aggregateOperationTime = Stopwatch.createStarted();
            computeAggregateOperation(icdbQuery, record);
            statistics.setAggregateOperationTime( statistics.getAggregateOperationTime()+aggregateOperationTime.elapsed(ICDBTool.TIME_UNIT));
        }

        return verified;
    }

    @Override
    /**
     * for RSA_AGGREGATE , get aggregate message by modular multiplication of messages
     * for SHA_AGGREGATE
     */
    protected boolean aggregateVerifyRecord(Record record, ICDBQuery icdbQuery) {

        final StringBuilder builder = new StringBuilder();

        int index = 0;
        List<String> tableList=icdbQuery.queryTableName;
        int tableIndex=0;

        for (Field<?> attr : record.fields()) {

            if (!attr.getName().equals("serial")) {
                final Object value = record.get(index);
                builder.append(value);
                builder.append(delimeter);
                index++;

            } else {


               // final byte[] signature = (byte[]) record.get(index);
                final long serial = (long) record.get(index );


                 String data = builder.toString();
                totalDataSize+=data.getBytes().length;

                //concat table name to the end
//                for (String table:icdbQuery.queryTableName) {
//                    data=data.concat(table.toLowerCase());
//                }
                data=data.concat(tableList.get(tableIndex).toLowerCase());
                tableIndex++;

                //check the ICRL(OLD)
//                if (!icrl.contains(serial)) {
//                    return false;
//                }

                //(NEW)
                if(ICDBTool.ICRLmap.containsKey(String.valueOf(serial).hashCode()))
                    return false;

                //generate aggregate message for RSA and regenerate signature for AES and SHA
                if (codeGen.getAlgorithm()== AlgorithmType.RSA_AGGREGATE){
                    final byte[] serialBytes = ByteBuffer.allocate(8).putLong(serial).array();
                    final byte[] dataBytes = data.getBytes(Charsets.UTF_8);
                    final byte[] allData = ArrayUtils.addAll(dataBytes, serialBytes);

                  //  totalDataSize+=dataBytes.length;
                    totalSerialSize+=serialBytes.length;
                    //test for RSA without sha hash!
                    RSASHA1Signer signer=new RSASHA1Signer(key.getModulus(),key.getExponent());
                    message = message.multiply(new BigInteger(signer.computehash(allData))).mod(key.getModulus());

                }else{
                    sigBuilderClient.append(Hex.toHexString(regenerateSignature(serial,data)));
                }
                //if delete query, add the serials to be revoked in the list
                if (icdbQuery.isDeleteQuery)
                    icdbQuery.serialsToBeRevoked.add(serial);
                builder.setLength(0);

                //for join queries
                if (record.size() == index + 1)
                    break;
                else {

                    index ++;
                }
            }


        }

        if (icdbQuery.isAggregateQuery) {
            Stopwatch aggregateOperationTime = Stopwatch.createStarted();
            computeAggregateOperation(icdbQuery, record);
            statistics.setAggregateOperationTime( statistics.getAggregateOperationTime()+aggregateOperationTime.elapsed(ICDBTool.TIME_UNIT));
        }

        return  true;
    }





}
