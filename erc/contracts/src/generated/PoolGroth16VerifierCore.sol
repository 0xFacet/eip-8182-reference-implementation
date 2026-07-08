// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract PoolGroth16VerifierCore {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 20491192805390485299153009773594534940189261866228447918068658471970481763042;
    uint256 constant alphay  = 9383485363053290200918347156157836566562967994039712273449902621266178545958;
    uint256 constant betax1  = 4252822878758300859123897981450591353533073413197771768651442665752259397132;
    uint256 constant betax2  = 6375614351688725206403948262868962793625744043794305715222011528459656738731;
    uint256 constant betay1  = 21847035105528745403288232691147584728191162732299865338377159692350059136679;
    uint256 constant betay2  = 10505242626370262277552901082094356697409835680220590971873171140371331206856;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 16319842809234930565276353339513116963806075341424174091770407058954008960673;
    uint256 constant deltax2 = 16465998158704508438959261658398597815465735477780183276841295378828288084183;
    uint256 constant deltay1 = 14793267925154660265291088144223976475368330354294896551045953381843909084214;
    uint256 constant deltay2 = 14156164230897528876095198164736882128833238253917110319497895324450663866014;

    
    uint256 constant IC0x = 7172075981892956773427108106035478078312006721762116440023920466844103877341;
    uint256 constant IC0y = 21123020606801832277400244896335523435604174369790450995877740728617033074340;
    
    uint256 constant IC1x = 8645985646587904073309395082417889375312434874918343582714032650114242329546;
    uint256 constant IC1y = 15504201186905289806967583959366810469174080559538898793856252505022676668207;
    
    uint256 constant IC2x = 15527957114051265775016067563871596761436085339305743227711009113199982375982;
    uint256 constant IC2y = 14563087959355126584206419954197778632820277934451927294099172533456159214237;
    
    uint256 constant IC3x = 12044179722580940556200995577062621116774122385501438269227238371686516462657;
    uint256 constant IC3y = 13830835170058243364822374939617617172483554685029989382294212960666825604700;
    
    uint256 constant IC4x = 7969924270414055222565928302815612061862629702211719644590050515805616278576;
    uint256 constant IC4y = 6037165326562528150218930527106625340030819433192612718304751855178202860693;
    
    uint256 constant IC5x = 4831028761199021387445126339357167500134384950898546169308803072572901404928;
    uint256 constant IC5y = 6120301362822114546754978679210465021743219923095705892338494136472464551718;
    
    uint256 constant IC6x = 7595921847643404432718046542649028328871137506240800099156364382727829556964;
    uint256 constant IC6y = 5340046868451065335307754071181601021156677999580866035781324799306950343066;
    
    uint256 constant IC7x = 280460691372510747581539833383996738269097254461702239076388462085408154381;
    uint256 constant IC7y = 14139036433276802286519380342809193806457031020724829436704805514666544663322;
    
    uint256 constant IC8x = 21332112240537502277119918727352863271174817632148671171629078787390135245695;
    uint256 constant IC8y = 13713312553399144411489806397125541760677729490369006563030248091584418801139;
    
    uint256 constant IC9x = 15952144759274863992909345931007516286599988209025125942035412274820232326849;
    uint256 constant IC9y = 8650121554502048713814125802534211866302602776483314391276652187163259619846;
    
    uint256 constant IC10x = 17635996668536706257546394548841025394615426373706400454577220547679950269413;
    uint256 constant IC10y = 5362223234983482492149449036136220641642234447971296533301931206593749496474;
    
    uint256 constant IC11x = 15992437118387840184222120254346366984005951276028240830029314929384592911634;
    uint256 constant IC11y = 20584560981970085590607357281757114011339312008142316023462751927165431115294;
    
    uint256 constant IC12x = 17646158002425875921763784388710972022596321765070141969935472631466417808304;
    uint256 constant IC12y = 15858334731599023678216786715326922304824405457196908281613284907124691847146;
    
    uint256 constant IC13x = 17012190503717051912363180725441517770728990258229327139200292164101344474489;
    uint256 constant IC13y = 13259548525322487912317433472211955662314607939880053382380286196303935360372;
    
    uint256 constant IC14x = 20036722697833902360025033161005532133886126464705336515539371289964544034779;
    uint256 constant IC14y = 14172073199620270134394353952264297081742584587864975109046765349879776961279;
    
    uint256 constant IC15x = 1188731528603427710219181460997275301493507686326361240865935138217138300234;
    uint256 constant IC15y = 11616674907698368075691610642581956515872387040834464048867955234132606518393;
    
    uint256 constant IC16x = 5867347824897865120634829080262510013934148803127693630371454965140595274531;
    uint256 constant IC16y = 7976186217917517645885485289624752796473957582029556783467459613385084735499;
    
    uint256 constant IC17x = 478528080481836761359500129517430990839658074486383333375524168021929232447;
    uint256 constant IC17y = 6478279029970777791620734771419728382649294276094800848347182509182349244892;
    
    uint256 constant IC18x = 8865863116818007400998769039829788818278854781488554398821891387944477095542;
    uint256 constant IC18y = 18499289916327064194323343631874982618141172758638284440528260694449955316008;
    
    uint256 constant IC19x = 8680407719856297258014249019906332642972189173130735240927130568022261771907;
    uint256 constant IC19y = 11673356671101178517670346891660060427822708842611327510760252525184001516293;
    
    uint256 constant IC20x = 12171063281095812668819605356684405916301263274396974232660809430737021228378;
    uint256 constant IC20y = 7035745419187434479442207496324640103379621802686572906788903491158790379899;
    
    uint256 constant IC21x = 3944206814919853573530302210600426499567386868342401794214218973018491980071;
    uint256 constant IC21y = 19304445887169442595570053985913450350048552584367251854407534723081133868230;
    
    uint256 constant IC22x = 987361372183980996639868302349761396283936978486608313305352097945227711392;
    uint256 constant IC22y = 14071303539496588343046047635108329605568305806479297682955511874916929034159;
    
    uint256 constant IC23x = 10406339476559824657938850717854522858233390584547999624143091757638961012369;
    uint256 constant IC23y = 19370718543982976190536059212318328468418045911469620814221259530541419902991;
    
    uint256 constant IC24x = 12674129916266211366238864418770764792923619970188355610658097837669634859865;
    uint256 constant IC24y = 12176102699760735693982766858856809619582737362752181720876774692523398727754;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[24] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                
                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                
                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))
                
                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))
                
                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))
                
                g1_mulAccC(_pVk, IC20x, IC20y, calldataload(add(pubSignals, 608)))
                
                g1_mulAccC(_pVk, IC21x, IC21y, calldataload(add(pubSignals, 640)))
                
                g1_mulAccC(_pVk, IC22x, IC22y, calldataload(add(pubSignals, 672)))
                
                g1_mulAccC(_pVk, IC23x, IC23y, calldataload(add(pubSignals, 704)))
                
                g1_mulAccC(_pVk, IC24x, IC24y, calldataload(add(pubSignals, 736)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            
            checkField(calldataload(add(_pubSignals, 480)))
            
            checkField(calldataload(add(_pubSignals, 512)))
            
            checkField(calldataload(add(_pubSignals, 544)))
            
            checkField(calldataload(add(_pubSignals, 576)))
            
            checkField(calldataload(add(_pubSignals, 608)))
            
            checkField(calldataload(add(_pubSignals, 640)))
            
            checkField(calldataload(add(_pubSignals, 672)))
            
            checkField(calldataload(add(_pubSignals, 704)))
            
            checkField(calldataload(add(_pubSignals, 736)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
