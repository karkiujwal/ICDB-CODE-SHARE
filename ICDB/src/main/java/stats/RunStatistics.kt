package stats

/**
 * Collects statistics about a run
 *
 * Created on 9/4/2016
 * @author Dan Kondratyuk
 */
data class RunStatistics(
    // Data collected as the run progresses
    var run: Long = 0,
    var queryFetchSize: Long = 0,
    var queryConversionTime: Long = 0,
    var dataFetchTime: Long = 0,
    var verificationTime: Long = 0,
    var executionTime: Long = 0,
    var aggregateOperationTime: Long = 0,
    var aggregateRecordFetchTime: Long = 0,
    var aggregateSigGenerationTime: Long = 0,
    var AGG_final_verificationTime: Long = 0,
    var icrlRevoketime: Long = 0,
    var totalDataSize: Long = 0,
    var totalSerialSize: Long = 0,
    var totalICSize: Long = 0

) {
    fun list(): List<Long> = listOf(
        run,
        queryFetchSize,
        queryConversionTime,
        dataFetchTime,
        verificationTime,
        executionTime,
        aggregateOperationTime,
            aggregateRecordFetchTime,
            aggregateSigGenerationTime,
            AGG_final_verificationTime,
            icrlRevoketime,
            totalDataSize,
            totalSerialSize,
            totalICSize
    )
}