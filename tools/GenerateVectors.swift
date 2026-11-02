import Foundation
@main struct Vectors {
 static func main() {
  for key in ["hello", "", "ed01junk", String(repeating:"AB",count:32),"ED01"+String(repeating:"AB",count:32)] + (0..<100).map({"peer-\($0)"}) {
   print("key\t\(Data(key.utf8).base64EncodedString())\t\(Data(KeyDifficulty.canonicalRawHex(key).utf8).base64EncodedString())\t\(KeyDifficulty.keyWorkBits(key))")
  }
  for threshold: UInt64 in [0,1,3,100,1001,UInt64.max] {
   var line=CreditLine(peerA:PeerID(publicKey:"a"),peerB:PeerID(publicKey:"b"),threshold:threshold)
   for i in 0..<80 {
    switch i%5 { case 0:line.adjustBalance(by:Int64(i*100-999));case 1:line.recordPartialSettlement(workValue:100);case 2:line.recordSettlement();case 3:line.recordMissedSettlement();default:line.adjustBalance(by:Int64.max) }
    print("credit\t\(threshold)\t\(i)\t\(line.balance)\t\(line.sequence)\t\(line.threshold)\t\(line.successfulSettlements)\t\(line.availableCapacity)\t\(line.debtPressure)")
   }
  }
  for i in 0..<100 {
   let nonce=Data((0..<32).map { UInt8(($0+i)%256) })
   let challenge=Challenge(nonce:nonce,boundPeer:PeerID(publicKey:"peer-\(i)"),difficulty:8)
   var counter:UInt64=0
   while true {
    var little=counter.littleEndian
    let solution=withUnsafeBytes(of:&little) { Data($0) }
    if challenge.meetsTarget(solution:solution) {
     print("challenge\t\(i)\t\(nonce.base64EncodedString())\t\(solution.base64EncodedString())")
     break
    }
    counter += 1
   }
  }
  let now=ContinuousClock.now
  let config=TallyConfig(decayHalfLife:10,exchangeBaseline:100)
  for i in 0..<100 {
   var evidence=PeerEvidence(now:now)
   evidence.recordSent(i*3,at:now,halfLife:10)
   evidence.recordReceived(i*11,at:now,halfLife:10)
   evidence.recordChallengeWork(i,at:now,halfLife:10)
   for _ in 0..<(i%5) {evidence.recordProtocolViolation(at:now,halfLife:10)}
   let score=evidence.admissionScore(for:PeerID(publicKey:"peer-\(i)"),at:now.advanced(by:.seconds(i)),config:config)
   print("evidence\t\(i)\t\(score)")
  }
 }
}
