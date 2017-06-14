package io;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import io.destination.FileDestination;
import main.ICDBTool;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jooq.tools.StringUtils;

import com.google.common.base.Charsets;
import com.google.common.base.Stopwatch;

import crypto.CodeGen;
import crypto.Convert;
import main.args.option.Granularity;
import io.source.FileSource;
import org.jooq.util.derby.sys.Sys;
import verify.serial.AbstractIcrl;
import verify.serial.Icrl;

/**
 * A FileConverter takes an input DB data file and generates a converted ICDB
 * data file. This class only supports MySQL for now.
 *
 * Created 5/8/2016
 * @author Dan Kondratyuk
 */
public class FileConverter {

	private final CodeGen codeGen;
	private final Granularity granularity;
	private final DBConnection db;

	private  String delimeter;

    private final AbstractIcrl icrl = Icrl.Companion.init();

	private static final Logger logger = LogManager.getLogger();

	public FileConverter(DBConnection db,CodeGen codeGen, Granularity granularity) {
		this.codeGen = codeGen;
		this.granularity = granularity;
		this.db = db;
		delimeter=",";
	}

	public void convertFile(final File input, final File output) {
		Stopwatch convertTime = Stopwatch.createStarted();

		try {
			// Parse the csv

			final Stream<List<String>> csvInput = FileSource.stream(input);
            final FileDestination csvOutput = new FileDestination(output);

			switch (granularity) {
                case TUPLE:
                    csvOutput.write(convertLineOCT(csvInput,input.getName().toLowerCase()));
                    csvInput.close();
                    break;
                case FIELD:
                    csvOutput.write(convertLineOCF(csvInput,input.getName().toLowerCase()));
                    csvInput.close();
                    break;
			}
		} catch (IOException e) {
			logger.error("Unable to convert file {}: {}", input.getName(), e.getMessage());
		}

		logger.debug("Converted table {} in {}", input.getName(), convertTime.elapsed(ICDBTool.TIME_UNIT));
	}

	private Stream<List<String>> convertLineOCT(Stream<List<String>> csvInput, String tablename) throws IOException {
		String[] table =tablename.split("\\.");
        return csvInput.map(line -> {
        	//need to concat the table name
            // Combine the list into a string

			String data="";
			//add delimeter to each of the attribute data
			for (String field : line) {
				data=data.concat(field);
				data=data.concat(delimeter);
			}

            // String data = StringUtils.join(line.toArray());
			data=data.concat(table[0]);
            final byte[] dataBytes = data.getBytes(Charsets.UTF_8);
            convertLine(line, dataBytes, codeGen, icrl);

            return line;
        });
	}

	private Stream<List<String>> convertLineOCF(Stream<List<String>> csvInput, String tablename) throws IOException {
		List <Integer> primarykeyindexes= new ArrayList<>();
		List <String> attributelist= new ArrayList<>();
     	List<String> collector = new ArrayList<>();
		String[] table =tablename.split("\\.");



	    return csvInput.map(line -> {

	    	//get the primarykey index from the csv header i.e, first line
			if(primarykeyindexes.size()<=0){
				List<String>primaryKeysList=db.getPrimaryKeys(table[0]);
				Collections.sort(primaryKeysList, String.CASE_INSENSITIVE_ORDER);
				primarykeyindexes.addAll(getprimaryKeyIndex(line,primaryKeysList));
				attributelist.addAll(getAttributeList(line));

			}
			collector.clear();
            collector.addAll(line);
			int attrIndex=0;
            for (String field : line) {


            	field=field.concat(delimeter);
            	//need to concat with primary key and table name
				for (Integer index:primarykeyindexes) {
					field=field.concat(line.get(index));
				}


				//concat attribute name
				field=field.concat(attributelist.get(attrIndex));
				attrIndex++;

				//concat table name
				field=field.concat(table[0]);


                final byte[] dataBytes = field.getBytes(Charsets.UTF_8);
                convertLine(collector, dataBytes, codeGen, icrl);
            }

            return collector;
        });
	}

	/**
	 * Given some data, this method generates codes (svc + serial) from it and
	 * adds them to the end of the supplied list
	 * 
	 * @param collector the list to collect the codes
	 */
	private static void convertLine(final List<String> collector, byte[] data, CodeGen codeGen, AbstractIcrl icrl) {
        final long serial = icrl.addNext();
        final String serialString = Long.toString(serial);

		final byte[] serialBytes = ByteBuffer.allocate(8).putLong(serial).array();
		final byte[] allData = ArrayUtils.addAll(data, serialBytes);

		// Generate the signature
		final byte[] signature = codeGen.generateSignature(allData);
		final String signatureString = Convert.toBase64(signature);


		// Write the line
		collector.add(signatureString);
		collector.add(serialString);
	}

	/**
	 * get the index of the primary keys from the csv file headers
	 * @param headerlist
	 * @param primarykeys
	 * @return
	 */
	private List <Integer> getprimaryKeyIndex(List<String> headerlist,List<String> primarykeys ){
		List<Integer> primaryKeyIndex=new ArrayList<>();
		int index=0;
		for (String field:headerlist) {

			for (String primarkey:primarykeys) {
			if(field.equalsIgnoreCase(primarkey)){
				primaryKeyIndex.add(index);
				break;
			}
			}
		index++;
		}
		return  primaryKeyIndex;

	}

	/**
	 * get the list of attributes in a table
	 * @param headerlist
	 * @return
	 */
	private List <String> getAttributeList(List<String> headerlist ){
		List<String> attributeList=new ArrayList<>();
		for (String field:headerlist) {
			attributeList.add(field.toLowerCase());
		}
		return  attributeList;

	}

}
