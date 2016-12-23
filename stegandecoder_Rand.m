function [msg] = stegandecoder_Rand(img,enc_key,randSeed)
% STEGANDECODER_RAND: This function "reveals" hidden messages by reversing 
%   the processing steps completed by the STEGANCODER_RAND Function. This
%   function differs from the STEGANDECODER Function in that it must
%   replicate the random encoding pattern to "find" the correct values.
%
% INPUTS:
% - img: This is image contains a hidden message that needs to be decoded.
% - enc_key: This is the Encryption Key used for Symmetric XOR Decryption.
%           THIS MUST BE THE SAME AS ENCRYPTION STEP FOR SUCCESSFUL 
%           DECRYPTION!
% - randSeed: This initializes the Random Number Generator used to decode
%           the message in the "Canvas" image. THIS VALUE MUST BE THE SAME
%           AS ENCRYPTION STEP TO SUCCESSFULLY DECODE THE MESSAGE!
%
% OUTPUTS:
% - msg: This output file will either be a grayscale image or a hidden text
%           message that was encoded into the original image.

%% David Pipkorn and Preston Weisbrot
% Project: Steganography - Hidden Messages in Images

%% Step 1a: Recover Header Set
% Random Permutation Set
[canM,canN,chan]=size(img);
canvas_Dim = canM * canN;
% Ensuring Dimension is Divisible by 3; RESHAPE Function will fail
% otherwise.
canTest = rem(canvas_Dim,3);
if canTest ~= 0
    canvas_Dim = canvas_Dim - canTest;
end

rng(randSeed); % Initialize Random Number Generator to a "Common" State. We 
               %   need to use the SAME value as the Encoding Steps.
randSet = randperm(canvas_Dim);     % Random Pixel Set.
randGroup = reshape(randSet,[],3);  % Final Pixel Groupings (3 pixels/grp).

% Initialize Header Holder Set
header = [];

for z = 1:8;
    temp = zeros(1,8);
    temp_loc = randGroup(z,:);
    
    % Isolate First 3 Header Values RGB
    % ---------------------------------
    [row1,col1] = ind2sub([canM,canN],temp_loc(1));
    % Red    
    temp(1,1) = mod(img(row1,col1,1),2);    
    
    % Green
    temp(1,2) = mod(img(row1,col1,2),2);
    
    % Blue
    temp(1,3) = mod(img(row1,col1,3),2);
    
    % Isolate Second 3 Header Values BGR
    % ---------------------------------
    [row2,col2] = ind2sub([canM,canN],temp_loc(2));
    
    % Blue
    temp(1,4) = mod(img(row2,col2,3),2);
    
    % Green
    temp(1,5) = mod(img(row2,col2,2),2);
    
    % Red    
    temp(1,6) = mod(img(row2,col2,1),2);    
    
    % Isolate Last 2 Header Values RG_
    % ---------------------------------
    [row3,col3] = ind2sub([canM,canN],temp_loc(3));
    % Red    
    temp(1,7) = mod(img(row3,col3,1),2);    
    
    % Green
    temp(1,8) = mod(img(row3,col3,2),2);
    
    % Convert Recovered Word to STRING and Append to Header
    tempstr = num2str(temp);
    header = vertcat(header,tempstr);
end

%% Step 1b: Header Analysis - Decrypt and Determine Message Dimensions
% key = 42;  % Used for Testing Phase
msg_head_set = bin2dec(header);
temp_head = bitxor(uint8(msg_head_set),uint8(enc_key));

% Case 1: If the Header starts with 't' it is a text file.
% Case 2: If the Header DOESN'T start with 't' then the message is an image
%   with the dimensions described in the header.
if temp_head(1) == 116
    % CASE 1: Text Set
    dim1 = char(temp_head(2:8));
    m = str2double(dim1);
    n = 1;    
else
    % CASE 2: Image Set
    % Determine Dimensions from Header Values
    tempm = char(temp_head(1:4));
    tempn = char(temp_head(5:8));
    m = str2double(tempm');
    n = str2double(tempn');    
end


%% Step 2: Isolate Potential Message
% Recall in Step 5 of the STEGANCODER Function we used a RGBBGRRG Cycle to
%   encode the message set. In this step we need to reverse this process
%   using MODULO arithmatic.

z = 0;

enc_msg = [];
stopmax = (m * n);

for z = 1:stopmax
    temp = zeros(1,8);
    temp_loc = randGroup(z+8,:);
    
    % Isolate First 3 Header Values RGB
    % ---------------------------------
    [row1,col1] = ind2sub([canM,canN],temp_loc(1));
    % Red    
    temp(1,1) = mod(img(row1,col1,1),2);    
    
    % Green
    temp(1,2) = mod(img(row1,col1,2),2);
    
    % Blue
    temp(1,3) = mod(img(row1,col1,3),2);
    
    % Isolate Second 3 Header Values BGR
    % ---------------------------------
    [row2,col2] = ind2sub([canM,canN],temp_loc(2));
    
    % Blue
    temp(1,4) = mod(img(row2,col2,3),2);
    
    % Green
    temp(1,5) = mod(img(row2,col2,2),2);
    
    % Red    
    temp(1,6) = mod(img(row2,col2,1),2);    
    
    % Isolate Last 2 Header Values RG_
    % ---------------------------------
    [row3,col3] = ind2sub([canM,canN],temp_loc(3));
    % Red    
    temp(1,7) = mod(img(row3,col3,1),2);    
    
    % Green
    temp(1,8) = mod(img(row3,col3,2),2);
    
    % Convert Recovered Word to STRING and Append to Message Set
    tempstr = num2str(temp);
    enc_msg = vertcat(enc_msg,tempstr);
end

%% Step 3: Decryption Step
% key = 42;  % Used for Test Phase
msg_dec_set = bin2dec(enc_msg);
msg_dec = bitxor(uint8(msg_dec_set),uint8(enc_key));
% msg_dec_set = dec2bin(msg_dec,8);

%% Step 4: Message Prep
if temp_head(1) == 116
    % CASE 1: Text Set
    msg_set = msg_dec;
    msg_out = char(msg_set');
    output = msg_out;
else
    % CASE 2: Image Set
    % Determine Dimensions from Header Values
    tempm = char(temp_head(1:4));
    tempn = char(temp_head(5:8));
    m = str2double(tempm');
    n = str2double(tempn');
    
    % Reshape Message Set into an Image Output
    msg_set = msg_dec;
    
    count = 1;
    msg_out = uint8(zeros(m,n));
    for y = 1:m
        for x = 1:n
            msg_out(y,x) = msg_set(count);
            count = count + 1;
        end
    end
    output = im2uint8(msg_out);
    
end


%% Step 5: Final Output
msg = output;
end